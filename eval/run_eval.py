#!/usr/bin/env python3
"""
chainsaw-eval evaluator

Waits for each scenario container to accept SSH, runs the Chainsaw binary
against it, parses the evidence.json output, and prints a comparison table.
Writes results/summary.md and results/summary.json.

Usage:
    python3 eval/run_eval.py [options]

Options:
    --chainsaw PATH     Path to Chainsaw binary     (default: ../chainsaw/chainsaw)
    --key PATH          SSH private key             (default: keys/eval_key)
    --host HOST         Docker host IP              (default: 127.0.0.1)
    --output DIR        Results root directory      (default: results)
    --scenario NAME     Run only this scenario (repeatable; default: all)
    --ssh-timeout SEC   Seconds to wait for SSH     (default: 90)
    --no-wait           Skip SSH readiness check
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Scenario registry
# ---------------------------------------------------------------------------

# Scenario tiers — each package runs in four forensic states.
# Ports are assigned as: base_port + (tier_index * 10)
#   S1 = base      Full Visibility    (all artifacts present)
#   S2 = base+10   Partial Cleanup    (pip cache retained, package uninstalled)
#   S3 = base+20   Aggressive Cleanup (cache + package removed; shell history only)
#   S4 = base+30   Persistence-Only   (only .pth file survives)
SCENARIO_TIERS: list[tuple[str, str, int]] = [
    # (package, tier_label, port)
    # Ports: base + (tier_index * 10), column order: litellm=01, num2words=02, telnyx=03, ultralytics=04
    ("litellm",      "s1", 2201),
    ("num2words",    "s1", 2202),
    ("telnyx",       "s1", 2203),
    ("ultralytics",  "s1", 2204),
    ("litellm",      "s2", 2211),
    ("num2words",    "s2", 2212),
    ("telnyx",       "s2", 2213),
    ("ultralytics",  "s2", 2214),
    ("litellm",      "s3", 2221),
    ("num2words",    "s3", 2222),
    ("telnyx",       "s3", 2223),
    ("ultralytics",  "s3", 2224),
    # S4: packages without .pth mechanism have only shell history remaining
    ("litellm",      "s4", 2231),
    ("num2words",    "s4", 2232),
    ("telnyx",       "s4", 2233),
    ("ultralytics",  "s4", 2234),
]

# Flat list used by the existing resolve_scenarios() / --scenario flag.
# Format: "{package}-{tier}" e.g. "litellm-s2"
ALL_SCENARIOS: list[tuple[str, int]] = [
    (f"{pkg}-{tier}", port) for pkg, tier, port in SCENARIO_TIERS
]


# ---------------------------------------------------------------------------
# Result data model
# ---------------------------------------------------------------------------

@dataclass
class IOCHit:
    indicator_id: str
    indicator_type: str
    matched_value: str
    description: str
    campaign: str


@dataclass
class CampaignResult:
    id: str
    confidence_pct: int
    total_artifacts: int
    kind_counts: dict[str, int]   # kind → count


@dataclass
class ScenarioResult:
    name: str
    port: int
    success: bool
    error: Optional[str] = None
    duration_ms: int = 0
    total_artifacts: int = 0
    critical_count: int = 0
    high_count: int = 0
    campaigns: list[CampaignResult] = field(default_factory=list)
    kind_counts: dict[str, int] = field(default_factory=dict)   # across all artifacts
    ioc_types: set[str] = field(default_factory=set)            # unique indicator_type
    ioc_campaigns: set[str] = field(default_factory=set)        # unique campaign names
    output_dir: Optional[str] = None


# ---------------------------------------------------------------------------
# SSH readiness check
# ---------------------------------------------------------------------------

def wait_for_ssh(host: str, port: int, timeout: int) -> bool:
    """Poll host:port until TCP connect succeeds or timeout expires."""
    deadline = time.monotonic() + timeout
    attempt = 0
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=2):
                return True
        except OSError:
            attempt += 1
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sleep = min(3, remaining)
            if attempt == 1:
                print(f"    waiting for SSH on :{port} ...", flush=True)
            time.sleep(sleep)
    return False


# ---------------------------------------------------------------------------
# Chainsaw runner
# ---------------------------------------------------------------------------

def run_chainsaw(
    binary: str,
    key: str,
    host: str,
    port: int,
    output_dir: str,
) -> tuple[bool, str]:
    """
    Invoke Chainsaw and return (ok, stderr_or_error).
    Runs: chainsaw --key KEY --user eval --port PORT --output DIR --ecosystem pypi HOST
    """
    os.makedirs(output_dir, exist_ok=True)
    cmd = [
        binary,
        "--key",       key,
        "--user",      "eval",
        "--port",      str(port),
        "--output",    output_dir,
        "--ecosystem", "pypi",
        host,
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except FileNotFoundError:
        return False, f"binary not found: {binary}"
    except subprocess.TimeoutExpired:
        return False, "chainsaw timed out after 120 s"

    if result.returncode != 0:
        return False, (result.stderr or result.stdout or "non-zero exit").strip()
    return True, result.stderr.strip()


# ---------------------------------------------------------------------------
# Evidence parser
# ---------------------------------------------------------------------------

def parse_evidence(evidence_path: str) -> ScenarioResult | None:
    """Parse evidence.json and return a partially-filled ScenarioResult."""
    try:
        with open(evidence_path) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        return None

    meta = data.get("meta", {})

    # Campaign summaries
    campaigns: list[CampaignResult] = []
    for c in data.get("campaigns", []):
        kc = {entry["kind"]: entry["count"] for entry in c.get("kind_counts", [])}
        campaigns.append(CampaignResult(
            id=c["id"],
            confidence_pct=c.get("confidence_pct", 0),
            total_artifacts=c.get("total_artifacts", 0),
            kind_counts=kc,
        ))

    # Per-artifact kind counts and IOC aggregation
    kind_counts: dict[str, int] = {}
    ioc_types: set[str] = set()
    ioc_campaigns: set[str] = set()

    for artifact in data.get("artifacts", []):
        kind = artifact.get("kind", "unknown")
        kind_counts[kind] = kind_counts.get(kind, 0) + 1
        for match in artifact.get("ioc_matches", []):
            if t := match.get("indicator_type"):
                ioc_types.add(t)
            if camp := match.get("campaign"):
                ioc_campaigns.add(camp)

    # Partial result — success/name/port filled by caller
    r = ScenarioResult(name="", port=0, success=True)
    r.duration_ms      = meta.get("duration_ms", 0)
    r.total_artifacts  = meta.get("total_artifacts", 0)
    r.critical_count   = meta.get("critical_count", 0)
    r.high_count       = meta.get("high_count", 0)
    r.campaigns        = campaigns
    r.kind_counts      = kind_counts
    r.ioc_types        = ioc_types
    r.ioc_campaigns    = ioc_campaigns
    return r


# ---------------------------------------------------------------------------
# Reporting helpers
# ---------------------------------------------------------------------------

SEVERITY_SYMBOLS = {
    "critical": "CRIT",
    "high":     "HIGH",
    "medium":   "MED",
    "low":      "LOW",
    "info":     "INFO",
}

ARTIFACT_DISPLAY_ORDER = [
    "pth_file", "persistence", "cache_hit",
    "install_log", "lockfile_entry", "shell_history",
    "network_ioc", "temp_file",
]


def campaign_cell(r: ScenarioResult) -> str:
    if not r.campaigns:
        return "—"
    parts = [f"{c.id} ({c.confidence_pct}%)" for c in r.campaigns]
    return "; ".join(parts)


def kinds_cell(r: ScenarioResult) -> str:
    """Only include artifact kinds that actually appeared."""
    parts = []
    for kind in ARTIFACT_DISPLAY_ORDER:
        n = r.kind_counts.get(kind, 0)
        if n:
            short = kind.replace("_", "-")
            parts.append(f"{short}×{n}")
    # pick up any unexpected kinds not in the display order
    for kind, n in sorted(r.kind_counts.items()):
        if kind not in ARTIFACT_DISPLAY_ORDER and n:
            parts.append(f"{kind}×{n}")
    return ", ".join(parts) if parts else "—"


def ioc_types_cell(r: ScenarioResult) -> str:
    if not r.ioc_types:
        return "—"
    return ", ".join(sorted(r.ioc_types))


def _col_widths(rows: list[list[str]], headers: list[str]) -> list[int]:
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    return widths


def print_terminal_table(results: list[ScenarioResult]) -> None:
    headers = [
        "Scenario", "Campaigns (confidence)", "Artifacts",
        "Critical", "Artifact kinds", "IOC types", "Duration",
    ]
    rows = []
    for r in results:
        if not r.success:
            rows.append([
                r.name, f"ERROR: {r.error or 'unknown'}", "—", "—", "—", "—", "—",
            ])
        else:
            rows.append([
                r.name,
                campaign_cell(r),
                str(r.total_artifacts),
                str(r.critical_count),
                kinds_cell(r),
                ioc_types_cell(r),
                f"{r.duration_ms} ms",
            ])

    widths = _col_widths(rows, headers)
    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"

    def fmt_row(cells: list[str]) -> str:
        return "|" + "|".join(f" {c:<{widths[i]}} " for i, c in enumerate(cells)) + "|"

    print()
    print(sep)
    print(fmt_row(headers))
    print(sep.replace("-", "="))
    for row in rows:
        print(fmt_row(row))
        print(sep)
    print()


def _load_artifacts(output_dir: str) -> list[dict]:
    """Return the artifact list from evidence.json, or [] on failure."""
    try:
        with open(os.path.join(output_dir, "evidence.json")) as f:
            return json.load(f).get("artifacts", [])
    except (OSError, json.JSONDecodeError, KeyError):
        return []


def write_markdown_summary(results: list[ScenarioResult], path: str) -> None:
    # Build lookup: (package, tier) -> ScenarioResult
    by_key: dict[tuple[str, str], ScenarioResult] = {}
    for r in results:
        # name is e.g. "litellm-s1" — split on last "-s" occurrence
        parts = r.name.rsplit("-", 1)
        if len(parts) == 2:
            by_key[(parts[0], parts[1])] = r

    # Determine row/column order from SCENARIO_TIERS
    packages: list[str] = []
    tiers: list[str] = []
    for pkg, tier, _ in SCENARIO_TIERS:
        if pkg not in packages:
            packages.append(pkg)
        if tier not in tiers:
            tiers.append(tier)

    # Map package -> campaign id (from first result that has one)
    pkg_campaign: dict[str, str] = {}
    for (pkg, tier), r in by_key.items():
        if pkg not in pkg_campaign and r.campaigns:
            pkg_campaign[pkg] = r.campaigns[0].id

    def cell_kinds(r: ScenarioResult) -> str:
        """Artifact kinds detected in this result, formatted for a table cell."""
        if not r.success:
            return "ERROR"
        if not r.kind_counts:
            return "—"
        return " + ".join(
            k.replace("_", "-") for k in sorted(r.kind_counts)
        )

    def artifact_rows(r: ScenarioResult) -> list[str]:
        """Return markdown table rows for per-cell artifact detail."""
        artifacts = _load_artifacts(r.output_dir) if r.output_dir else []
        rows = []
        for a in artifacts:
            kind    = a.get("kind", "?")
            sev     = a.get("severity", "?")
            pkg     = a.get("package_name", "")
            ver     = a.get("package_version", "")
            pkg_str = f"{pkg}@{ver}" if ver else pkg
            source  = a.get("source", "?")
            apath   = a.get("path", "")
            note    = a.get("note", "")
            display = apath if apath else note
            if len(display) > 60:
                display = "…" + display[-57:]
            ioc_ids = [m.get("indicator_id", "?") for m in a.get("ioc_matches", [])]
            ioc_str = ", ".join(ioc_ids) if ioc_ids else "—"
            rows.append(
                f"| {kind} | {sev} | {pkg_str} | {source} | {ioc_str} | `{display}` |"
            )
        return rows

    lines = [
        "# chainsaw-eval Results",
        "",
        "PyPI-only evaluation against Datadog malicious-packages-dataset.",
        f"Generated: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
        "",
        "## Detection Matrix",
        "",
        "_Rows = campaigns. Columns = scenario tiers (S1–S4). Cells show artifact kinds detected._",
        "_S1 = full visibility · S2 = partial cleanup (cache retained) · S3 = aggressive cleanup · S4 = persistence-only_",
        "",
    ]

    # Build the cross-tab header
    tier_labels = " | ".join(t.upper() for t in tiers)
    lines.append(f"| Campaign | {tier_labels} |")
    lines.append("|" + "---|" * (len(tiers) + 1))

    for pkg in packages:
        campaign = pkg_campaign.get(pkg, pkg)
        cells = []
        for tier in tiers:
            r = by_key.get((pkg, tier))
            cells.append(cell_kinds(r) if r else "—")
        lines.append(f"| **{campaign}** | " + " | ".join(cells) + " |")

    lines += [
        "",
        "## Per-Cell Artifact Detail",
        "",
        "_Each section lists every artifact chainsaw collected. Use this to manually verify detections._",
        "",
    ]

    for pkg in packages:
        campaign = pkg_campaign.get(pkg, pkg)
        lines.append(f"### {campaign}")
        lines.append("")
        for tier in tiers:
            r = by_key.get((pkg, tier))
            tier_label = tier.upper()
            lines.append(f"#### {tier_label} — `{pkg}-{tier}`")
            if r is None:
                lines.append("_Scenario not run._")
                lines.append("")
                continue
            if not r.success:
                lines.append(f"**Collection failed:** `{r.error}`")
                lines.append("")
                continue
            camp_str = ", ".join(f"**{c.id}** ({c.confidence_pct}%)" for c in r.campaigns) if r.campaigns else "none"
            lines.append(f"Campaigns: {camp_str} · {r.total_artifacts} artifact(s) · {r.duration_ms} ms")
            rows = artifact_rows(r)
            if rows:
                lines.append("")
                lines.append("| Kind | Severity | Package | Source | IOC matched | Path / Note |")
                lines.append("|---|---|---|---|---|---|")
                lines.extend(rows)
            else:
                lines.append("")
                lines.append("_No artifacts collected._")
            if r.output_dir:
                lines.append("")
                lines.append(f"Evidence: `{r.output_dir}/evidence.json`")
            lines.append("")

    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


def write_json_summary(results: list[ScenarioResult], path: str) -> None:
    out = []
    for r in results:
        out.append({
            "scenario":        r.name,
            "port":            r.port,
            "success":         r.success,
            "error":           r.error,
            "duration_ms":     r.duration_ms,
            "total_artifacts": r.total_artifacts,
            "critical_count":  r.critical_count,
            "high_count":      r.high_count,
            "campaign_count":  len(r.campaigns),
            "campaigns": [
                {
                    "id":             c.id,
                    "confidence_pct": c.confidence_pct,
                    "total_artifacts": c.total_artifacts,
                    "kind_counts":    c.kind_counts,
                }
                for c in r.campaigns
            ],
            "kind_counts":   r.kind_counts,
            "ioc_types":     sorted(r.ioc_types),
            "ioc_campaigns": sorted(r.ioc_campaigns),
            "output_dir":    r.output_dir,
        })
    with open(path, "w") as f:
        json.dump(out, f, indent=2)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--chainsaw",    default="../chainsaw/chainsaw",
                   help="Path to chainsaw binary")
    p.add_argument("--key",         default="keys/eval_key",
                   help="SSH private key path")
    p.add_argument("--host",        default="127.0.0.1",
                   help="Docker host IP")
    p.add_argument("--output",      default="results",
                   help="Results root directory")
    p.add_argument("--scenario",    action="append", dest="scenarios",
                   help="Run only this scenario (repeatable)")
    p.add_argument("--ssh-timeout", type=int, default=90,
                   help="Seconds to wait for SSH readiness")
    p.add_argument("--no-wait",     action="store_true",
                   help="Skip SSH readiness check")
    return p.parse_args()


def resolve_scenarios(requested: list[str] | None) -> list[tuple[str, int]]:
    if not requested:
        return ALL_SCENARIOS
    valid = {name: port for name, port in ALL_SCENARIOS}
    chosen = []
    for name in requested:
        if name not in valid:
            print(f"ERROR: unknown scenario '{name}'. Valid: {list(valid)}", file=sys.stderr)
            sys.exit(1)
        chosen.append((name, valid[name]))
    return chosen


def main() -> None:
    args = parse_args()

    # Resolve paths relative to repo root (the directory above eval/)
    repo_root = Path(__file__).parent.parent
    chainsaw_bin = str((repo_root / args.chainsaw).resolve()
                       if not os.path.isabs(args.chainsaw)
                       else Path(args.chainsaw))
    key_path = str((repo_root / args.key).resolve()
                   if not os.path.isabs(args.key)
                   else Path(args.key))
    output_root = str((repo_root / args.output).resolve()
                      if not os.path.isabs(args.output)
                      else Path(args.output))

    scenarios = resolve_scenarios(args.scenarios)

    # Preflight checks
    if not os.path.isfile(chainsaw_bin):
        print(f"ERROR: chainsaw binary not found: {chainsaw_bin}", file=sys.stderr)
        print("  Build it with: cd ../chainsaw && go build ./cmd/chainsaw/", file=sys.stderr)
        sys.exit(1)
    if not os.path.isfile(key_path):
        print(f"ERROR: SSH key not found: {key_path}", file=sys.stderr)
        print("  Generate with: make keys", file=sys.stderr)
        sys.exit(1)

    print(f"chainsaw-eval — {len(scenarios)} scenario(s)")
    print(f"  binary : {chainsaw_bin}")
    print(f"  key    : {key_path}")
    print(f"  host   : {args.host}")
    print(f"  output : {output_root}")
    print()

    results: list[ScenarioResult] = []

    for name, port in scenarios:
        print(f"[{name}] port {port}")
        out_dir = os.path.join(output_root, name)

        # SSH readiness
        if not args.no_wait:
            ok = wait_for_ssh(args.host, port, args.ssh_timeout)
            if not ok:
                print(f"  TIMEOUT — SSH not ready after {args.ssh_timeout}s")
                results.append(ScenarioResult(
                    name=name, port=port, success=False,
                    error=f"SSH not ready after {args.ssh_timeout}s",
                ))
                continue
            print("  SSH ready")

        # Run Chainsaw
        print("  running chainsaw ...", flush=True)
        ok, detail = run_chainsaw(chainsaw_bin, key_path, args.host, port, out_dir)
        if not ok:
            print(f"  FAILED — {detail}")
            results.append(ScenarioResult(
                name=name, port=port, success=False, error=detail,
                output_dir=out_dir,
            ))
            continue

        # Parse output
        evidence_path = os.path.join(out_dir, "evidence.json")
        parsed = parse_evidence(evidence_path)
        if parsed is None:
            print("  evidence.json missing or unparseable")
            results.append(ScenarioResult(
                name=name, port=port, success=False,
                error="evidence.json missing or parse error",
                output_dir=out_dir,
            ))
            continue

        parsed.name = name
        parsed.port = port
        parsed.output_dir = out_dir

        camp_str = campaign_cell(parsed) if parsed.campaigns else "no campaigns"
        print(f"  done — {parsed.total_artifacts} artifacts, "
              f"{parsed.critical_count} critical, {camp_str}")
        results.append(parsed)

    # Output
    print_terminal_table(results)

    os.makedirs(output_root, exist_ok=True)
    md_path = os.path.join(output_root, "summary.md")
    js_path = os.path.join(output_root, "summary.json")
    write_markdown_summary(results, md_path)
    write_json_summary(results, js_path)
    print(f"Wrote {md_path}")
    print(f"Wrote {js_path}")


if __name__ == "__main__":
    main()
