#!/usr/bin/env bash
set -euo pipefail

# SCENARIO_MODE controls post-install cleanup to simulate forensic scenarios:
#   s1  Full Visibility    — package installed, all artifacts present (default)
#   s2  Partial Cleanup    — package uninstalled; pip wheel cache retained
#   s3  Aggressive Cleanup — package + cache removed; only shell history remains
#   s4  Persistence-Only   — all package artifacts removed; .pth file retained
MODE="${SCENARIO_MODE:-s1}"

log() { echo "[chainsaw-eval/${SCENARIO:-unknown}/${MODE}] $*"; }

# ---------------------------------------------------------------------------
# Package installation helper
# ---------------------------------------------------------------------------

install_pkg() {
    local pkg="$1"
    log "pip install $(basename "$pkg")"

    local target="$pkg"
    if [[ -d "$pkg" && -f "$pkg/setup.py" && ! -f "$pkg/pyproject.toml" ]]; then
        target=$(mktemp -d)
        cp -r "$pkg/." "$target/"
    fi

    pip3 install \
        --break-system-packages \
        --no-deps \
        --force-reinstall \
        --quiet \
        "$target" 2>&1 || log "WARNING: install exited non-zero for $pkg (continuing)"

    if [[ "$target" != "$pkg" ]]; then rm -rf "$target"; fi
}

# Extract normalized package name from a wheel or tarball filename.
# litellm-1.82.8-py3-none-any.whl  → litellm
# num2words-0.5.15.tar.gz          → num2words
pkg_name_from_file() {
    basename "$1" | sed 's/-[0-9].*//'
}

# Build a "pip install name==version" spec from a wheel or tarball filename.
# Used to write realistic shell history that the os/shell collector can parse.
# litellm-1.82.8-py3-none-any.whl → litellm==1.82.8
# num2words-0.5.15.tar.gz         → num2words==0.5.15
pkg_pip_spec() {
    local base
    base="$(basename "$1")"
    # Strip known extensions
    local noext="${base%.whl}"
    noext="${noext%.tar.gz}"
    noext="${noext%.zip}"
    # Name = everything before the first hyphen-digit sequence
    local name="${noext%%-[0-9]*}"
    # Version = the segment immediately following name-, up to the next hyphen
    local remainder="${noext#${name}-}"
    local version="${remainder%%-*}"
    if [[ -n "$version" && "$version" != "$noext" ]]; then
        echo "${name}==${version}"
    else
        echo "${name}"
    fi
}

# ---------------------------------------------------------------------------
# Strategy 1: pre-built distributions (.tar.gz / .whl anywhere under /packages)
# ---------------------------------------------------------------------------
mapfile -t tarballs < <(find /packages -name "*.tar.gz" -type f | sort)
mapfile -t wheels   < <(find /packages -name "*.whl"    -type f | sort)

filter_artifacts() {
    local -n _arr="$1"
    local filtered=()
    for p in "${_arr[@]}"; do
        if [[ "$p" != */enterprise/* && "$p" != */dist/* ]]; then
            filtered+=("$p")
        fi
    done
    _arr=("${filtered[@]+"${filtered[@]}"}")
}
filter_artifacts tarballs
filter_artifacts wheels

INSTALLED_FROM=""
INSTALLED_NAMES=()

if [[ ${#tarballs[@]} -gt 0 ]]; then
    for pkg in "${tarballs[@]}"; do
        install_pkg "$pkg"
        INSTALLED_NAMES+=("$(pkg_name_from_file "$pkg")")
    done
    INSTALLED_FROM="${tarballs[*]}"
elif [[ ${#wheels[@]} -gt 0 ]]; then
    for pkg in "${wheels[@]}"; do
        install_pkg "$pkg"
        INSTALLED_NAMES+=("$(pkg_name_from_file "$pkg")")
    done
    INSTALLED_FROM="${wheels[*]}"

# ---------------------------------------------------------------------------
# Strategy 2: source trees
# ---------------------------------------------------------------------------
else
    mapfile -t project_files < <(
        find /packages \( -name "pyproject.toml" -o -name "setup.py" \) -type f | sort
    )

    if [[ ${#project_files[@]} -eq 0 ]]; then
        log "WARNING: nothing installable found in /packages"
        exec /usr/sbin/sshd -D
    fi

    declare -A candidate_set
    for f in "${project_files[@]}"; do
        candidate_set["$(dirname "$f")"]=1
    done
    mapfile -t candidates < <(printf '%s\n' "${!candidate_set[@]}" | sort)

    roots=()
    for dir in "${candidates[@]}"; do
        nested=false
        for other in "${candidates[@]}"; do
            if [[ "$dir" != "$other" && "$dir" == "$other"/* ]]; then
                nested=true; break
            fi
        done
        [[ "$nested" == false ]] && roots+=("$dir")
    done

    if [[ ${#roots[@]} -eq 0 ]]; then
        log "WARNING: could not determine top-level source root(s)"
    else
        for dir in "${roots[@]}"; do install_pkg "$dir"; done
        INSTALLED_FROM="${roots[*]}"
    fi
fi

# ---------------------------------------------------------------------------
# Write shell history so os/shell collector has signal in every scenario.
# Use "name==version" format so the shell collector's pipInstallRe regex
# can extract the package name+version and match against the IOC database.
# Write to /home/eval/.bash_history — that is targetHome for the eval SSH
# user that chainsaw connects as.  Also write to /root/.bash_history so
# root-targeting forensic tools (and docker logs) see the same history.
# ---------------------------------------------------------------------------
EVAL_HIST="/home/eval/.bash_history"
ROOT_HIST="/root/.bash_history"
for src in $INSTALLED_FROM; do
    echo "pip3 install $(pkg_pip_spec "$src")" >> "$EVAL_HIST"
    echo "pip3 install $(pkg_pip_spec "$src")" >> "$ROOT_HIST"
done
chown eval:eval "$EVAL_HIST" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Direct filesystem removal — fast alternative to pip3 uninstall.
# Removes the dist-info dir and top-level package dir for a given package name.
# ---------------------------------------------------------------------------
remove_package_fs() {
    local name="$1"
    local normalized="${name//-/_}"
    local found=false

    # Collect dist-info dirs into an array first (avoids pipe/process-subst
    # interactions with set -e under some bash versions).
    local distinfos=()
    while IFS= read -r di; do
        distinfos+=("$di")
    done < <(find /usr/local/lib /usr/lib -maxdepth 6 \
        \( -name "${name}-*.dist-info" -o -name "${normalized}-*.dist-info" \) \
        -type d 2>/dev/null || true)

    for distinfo in "${distinfos[@]+"${distinfos[@]}"}"; do
        found=true
        local sitepkg
        sitepkg="$(dirname "$distinfo")"
        log "removing dist-info: $distinfo"
        rm -rf -- "$distinfo"                                      || true
        rm -rf -- "${sitepkg}/${name}" "${sitepkg}/${normalized}"  || true
        rm -f  -- "${sitepkg}/${name}.py" "${sitepkg}/${normalized}.py" || true
        log "removed ${name} from ${sitepkg}"
    done

    if [[ "$found" == "false" ]]; then
        log "WARNING: no dist-info found for $name"
    fi
}

# ---------------------------------------------------------------------------
# Capture .pth files before any cleanup (needed for s4 re-plant)
# ---------------------------------------------------------------------------
PTH_FILES=()
mapfile -t PTH_FILES < <(
    find /usr/local/lib /usr/lib -name "*.pth" -not -name "distutils-precedence.pth" \
      -not -path "*/python3/dist-packages/*" 2>/dev/null
)

# Stash .pth content now (before removal) so s4 can re-plant
declare -A pth_stash
for pth in "${PTH_FILES[@]+"${PTH_FILES[@]}"}"; do
    pth_stash["$pth"]=$(cat "$pth" 2>/dev/null || true)
done

# ---------------------------------------------------------------------------
# Scenario-specific cleanup
# ---------------------------------------------------------------------------
case "$MODE" in

  s1)
    log "S1: full visibility — no cleanup"
    ;;

  s2)
    # Populate the pip wheel cache with any wheels we installed from, then
    # remove the package from the filesystem.  The cache survives — that's the point.
    # Write to /home/eval/.cache/pip/wheels so the eval SSH user can read it.
    log "S2: caching wheels then removing package files"
    CACHE_DIR="/home/eval/.cache/pip/wheels"
    for whl in "${wheels[@]+"${wheels[@]}"}"; do
        H=$(sha256sum "$whl" | cut -c1-8)
        DST="$CACHE_DIR/${H:0:2}/${H:2:2}/${H:4:4}"
        mkdir -p "$DST"
        cp "$whl" "$DST/"
        chown -R eval:eval /home/eval/.cache
        log "cached $(basename "$whl") → $DST"
    done

    for name in "${INSTALLED_NAMES[@]+"${INSTALLED_NAMES[@]}"}"; do
        remove_package_fs "$name"
    done
    # Also remove .pth files — pip uninstall would have removed these
    for pth in "${PTH_FILES[@]+"${PTH_FILES[@]}"}"; do
        rm -f -- "$pth" && log "removed .pth: $pth" || true
    done
    ;;

  s3)
    # Remove package files, .pth files, AND wipe the pip cache.
    # Shell history written above is the only remaining signal.
    log "S3: removing package files, .pth files, and wiping pip cache"
    for name in "${INSTALLED_NAMES[@]+"${INSTALLED_NAMES[@]}"}"; do
        remove_package_fs "$name"
    done
    # Also remove any .pth files planted by the install (persistence artifacts)
    for pth in "${PTH_FILES[@]+"${PTH_FILES[@]}"}"; do
        rm -f -- "$pth" && log "removed .pth: $pth" || true
    done
    rm -rf /root/.cache/pip /home/eval/.cache/pip
    ;;

  s4)
    # Remove package files, wipe cache, then re-plant .pth files.
    log "S4: persistence-only — re-planting .pth after removal"

    for name in "${INSTALLED_NAMES[@]+"${INSTALLED_NAMES[@]}"}"; do
        remove_package_fs "$name"
    done
    rm -rf /root/.cache/pip /home/eval/.cache/pip

    for pth in "${!pth_stash[@]}"; do
        mkdir -p "$(dirname "$pth")"
        printf '%s' "${pth_stash[$pth]}" > "$pth"
        log "re-planted $pth"
    done
    ;;

  *)
    log "WARNING: unknown SCENARIO_MODE='$MODE', falling back to s1"
    ;;
esac

mkdir -p /run/sshd
log "SSH ready on port 22"
exec /usr/sbin/sshd -D
