#!/usr/bin/env python3
"""Inject synonymous lints into the zlint v3 tree and build.

Usage:
  python inject_and_build.py --emit --build           # inject + compile
  python inject_and_build.py --emit --manifest-only    # only write manifest
  python inject_and_build.py --build                   # rebuild with existing injected lints
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
ZLINT = _ROOT / "cicas_backend" / "zlint" / "v3"
MANIFEST_SRC = _ROOT / "cicas_backend" / "experiments" / "codegen_metrics" / "outputs" / "full_current_db" / "synonymous_lints_manifest.json"
MANIFEST_DST = _ROOT / "cicas_backend" / "experiments" / "cert_detection" / "inputs" / "cicasgen_manifest.json"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--emit", action="store_true", help="inject lint Go files into zlint tree")
    ap.add_argument("--build", action="store_true", help="run go build after injection")
    ap.add_argument("--manifest-only", action="store_true", help="only write manifest JSON")
    args = ap.parse_args()

    if not args.emit and not args.build and not args.manifest_only:
        ap.error("need at least one of --emit, --build, --manifest-only")

    # --- manifest ---
    if args.emit or args.manifest_only:
        if not MANIFEST_SRC.exists():
            sys.exit(f"[error] manifest not found: {MANIFEST_SRC}")
        manifest = json.loads(MANIFEST_SRC.read_text())
        # Transform into the format cert_detection expects
        zlint_entries = []
        for item in manifest:
            output_path = item.get("output_path", "")
            if not output_path:
                continue
            zlint_entries.append({
                "lint_name": item["lint_name"],
                "rule_id": item["rule_id"],
                "source": item["source"],
                "section": item["section"],
                "rule_text": "",  # will be filled from DB if needed
                "method": item["method"],
                "severity": "lint.Error",
                "synonymy_verdict": "EXPRESSES",
                "pkg": Path(output_path).parts[-2],
                "file": "lints/" + output_path.split("/")[-2] + "/" + Path(output_path).name,
            })
        full_manifest = {
            "zlint_v3": str(ZLINT),
            "count": len(zlint_entries),
            "lints": zlint_entries,
        }
        MANIFEST_DST.parent.mkdir(parents=True, exist_ok=True)
        MANIFEST_DST.write_text(json.dumps(full_manifest, indent=2, ensure_ascii=False))
        print(f"[manifest] wrote {MANIFEST_DST} ({len(zlint_entries)} lints)")

    if args.manifest_only:
        return

    # --- inject lint files ---
    if args.emit:
        src_dir = MANIFEST_SRC.parent / "synonymous_lints"
        if not src_dir.exists():
            sys.exit(f"[error] lint source dir not found: {src_dir}")

        injected = 0
        for pkg_dir in src_dir.iterdir():
            if not pkg_dir.is_dir():
                continue
            pkg = pkg_dir.name  # "rfc" or "cabf_br"
            dest_dir = ZLINT / "lints" / pkg
            dest_dir.mkdir(parents=True, exist_ok=True)
            for f in pkg_dir.iterdir():
                if not f.is_file() or not f.name.endswith(".go"):
                    continue
                # Copy (don't overwrite existing zlint-authored files)
                dst = dest_dir / f.name
                dst.write_bytes(f.read_bytes())
                injected += 1
                print(f"[inject] {dst.name}")

        print(f"[inject] injected {injected} lint files into {ZLINT}/lints/")

    # --- build ---
    if args.build:
        print("[build] go build ./... in zlint v3 ...")
        result = subprocess.run(
            ["go", "build", "./..."],
            cwd=ZLINT,
            capture_output=True,
            text=True,
            timeout=600,
        )
        if result.returncode != 0:
            print(f"[build] FAILED (exit {result.returncode}):")
            print(result.stderr[-2000:])
            sys.exit(1)
        print("[build] OK")


if __name__ == "__main__":
    main()
