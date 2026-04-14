#!/usr/bin/env python3
"""
Reconstruct an installable ultralytics wheel from the Datadog malformed zip.

The zip stores files as:
  tmp/tmpqwqm_hzo/ultralytics/<rel_path>/<rel_path>
                               ^prefix^   ^dup nested^

We strip the prefix (everything up to and including the second ultralytics/ segment)
and the nested duplication to recover the original relative path, then package
the result as a proper wheel.

Usage:
  python3 build_ultralytics_wheel.py \
      --zip /path/to/2024-12-04-ultralytics-v8.3.41.zip \
      --out /path/to/output/dir
"""

import argparse
import io
import os
import re
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

PASSWORD = b"infected"
VERSION  = "8.3.41"
PKG      = "ultralytics"

# The zip stores installed files under this prefix (everything before the first
# occurrence of "ultralytics/<something>/ultralytics/<something>"):
#   tmp/tmpqwqm_hzo/ultralytics/
# followed by the relative path TWICE (the outer occurrence is the "directory"
# name that pip used as a fake key; the inner is the actual content).
#
# For a file at relative path  ultralytics/utils/downloads.py  the zip entry is:
#   tmp/tmpqwqm_hzo/ultralytics/ultralytics/utils/downloads.py/ultralytics/utils/downloads.py
#
# For dist-info:
#   tmp/tmpqwqm_hzo/ultralytics/ultralytics-8.3.41.dist-info/RECORD/ultralytics-8.3.41.dist-info/RECORD
#
# Strategy: find entries whose zip path ends with  /<rel> where <rel> appears
# earlier in the same path.  The relative path is everything after the last
# occurrence of the pivot token "tmpqwqm_hzo/ultralytics/" + one more component.

PIVOT = f"tmp/tmpqwqm_hzo/ultralytics/"


def extract_rel(member_name: str) -> str | None:
    """
    Return the relative package path for a zip member, or None if not applicable.

    Example:
      member = "tmp/tmpqwqm_hzo/ultralytics/ultralytics/utils/downloads.py/ultralytics/utils/downloads.py"
      returns "ultralytics/utils/downloads.py"
    """
    if not member_name.startswith(PIVOT):
        return None
    after_pivot = member_name[len(PIVOT):]  # "ultralytics/utils/downloads.py/ultralytics/utils/downloads.py"

    # The relative path is everything after "ultralytics/" (first component).
    # But it also appears duplicated at the end.  Find the pattern:
    #   <outer>/<inner>  where <inner> == <outer>
    # We do this by trying every prefix of after_pivot.
    parts = after_pivot.split("/")
    # Walk forward: the first N parts form <outer>, remaining parts start with same N parts
    for split in range(1, len(parts)):
        outer = "/".join(parts[:split])
        remaining = "/".join(parts[split:])
        if remaining == outer:
            return outer
    return None


def build_wheel(zip_path: str, out_dir: str) -> Path:
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        pkg_root = tmpdir / "pkg"
        pkg_root.mkdir()

        with zipfile.ZipFile(zip_path) as zf:
            zf.setpassword(PASSWORD)
            members = zf.infolist()

            extracted = 0
            skipped   = 0
            for info in members:
                rel = extract_rel(info.filename)
                if rel is None or info.is_dir():
                    skipped += 1
                    continue

                dest = pkg_root / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                try:
                    data = zf.read(info.filename)
                    dest.write_bytes(data)
                    extracted += 1
                except Exception as e:
                    print(f"  WARN: could not extract {info.filename}: {e}", file=sys.stderr)

        print(f"Extracted {extracted} files ({skipped} skipped)")

        # Build wheel using pip wheel or just zip it as a wheel manually
        # A wheel is a zip with:
        #   <package_files>/
        #   <name>-<version>.dist-info/
        wheel_name = f"{PKG}-{VERSION}-py3-none-any.whl"
        wheel_path = out_path / wheel_name

        with zipfile.ZipFile(wheel_path, "w", zipfile.ZIP_DEFLATED) as whl:
            for f in sorted(pkg_root.rglob("*")):
                if f.is_file():
                    arcname = f.relative_to(pkg_root)
                    whl.write(f, arcname)

        print(f"Built wheel: {wheel_path}  ({wheel_path.stat().st_size:,} bytes)")
        print(f"Contents sample:")
        with zipfile.ZipFile(wheel_path) as whl:
            names = whl.namelist()
            print(f"  {len(names)} entries")
            for n in sorted(names)[:10]:
                print(f"    {n}")
            print("    ...")

        return wheel_path


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--zip", required=True, help="Path to Datadog malicious zip")
    ap.add_argument("--out", required=True, help="Output directory for the wheel")
    args = ap.parse_args()

    wheel = build_wheel(args.zip, args.out)
    print(f"\nOutput: {wheel}")


if __name__ == "__main__":
    main()
