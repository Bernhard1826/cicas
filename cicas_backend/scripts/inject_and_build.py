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
MANIFEST_DIR = _ROOT / "cicas_backend" / "experiments" / "codegen_metrics" / "outputs" / "full_current_db"
SHIPPING_MANIFEST_SRC = MANIFEST_DIR / "shipping_lints_manifest.json"
ROW_FRAGMENT_MANIFEST_SRC = MANIFEST_DIR / "synonymous_lints_manifest.json"
MANIFEST_DST = _ROOT / "cicas_backend" / "experiments" / "cert_detection" / "inputs" / "cicasgen_manifest.json"


def _rule_text_by_id(path: Path) -> dict[int, str]:
    out: dict[int, str] = {}
    if not path.exists():
        return out
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        rid = rec.get("rule_id")
        text = (rec.get("text") or rec.get("rule_text") or "").strip()
        if rid is not None and text:
            out[int(rid)] = text
    return out


def _non_pass_status_from_go(path: Path) -> str:
    if not path.exists():
        return "lint.Error"
    text = path.read_text(errors="replace")
    for status in ("Fatal", "Error", "Warn", "Notice", "Info"):
        if f"Status: lint.{status}" in text:
            return f"lint.{status}"
    return "lint.Error"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--emit", action="store_true", help="inject lint Go files into zlint tree")
    ap.add_argument("--build", action="store_true", help="run go build after injection")
    ap.add_argument("--manifest-only", action="store_true", help="only write manifest JSON")
    ap.add_argument(
        "--manifest-source",
        choices=("shipping", "row-fragment"),
        default="shipping",
        help="shipping uses strict final-zlint synonymy; row-fragment is diagnostic only",
    )
    args = ap.parse_args()

    if not args.emit and not args.build and not args.manifest_only:
        ap.error("need at least one of --emit, --build, --manifest-only")

    zlint_entries = []
    manifest_src = (
        SHIPPING_MANIFEST_SRC
        if args.manifest_source == "shipping"
        else ROW_FRAGMENT_MANIFEST_SRC
    )

    # --- manifest ---
    if args.emit or args.manifest_only:
        if not manifest_src.exists():
            hint = ""
            if args.manifest_source == "shipping":
                hint = " Run run_codegen_synonymy.py --rejudge-shipping first."
            sys.exit(f"[error] manifest not found: {manifest_src}.{hint}")
        if args.manifest_source == "row-fragment":
            print("[warn] using row-fragment synonymy manifest; do not use this for certificate scans")
        manifest = json.loads(manifest_src.read_text())
        fallback_text = _rule_text_by_id(manifest_src.parent / "codegen_synonymy.jsonl")
        # Transform into the format cert_detection expects
        for item in manifest:
            output_path = item.get("output_path", "")
            if not output_path:
                continue
            rid = int(item["rule_id"])
            zlint_entries.append({
                "lint_name": item["lint_name"],
                "rule_id": rid,
                "source": item["source"],
                "section": item["section"],
                "rule_text": item.get("rule_text") or fallback_text.get(rid, ""),
                "method": item["method"],
                "severity": item.get("severity") or _non_pass_status_from_go(Path(output_path)),
                "synonymy_verdict": item.get("shipping_synonymy_verdict")
                                    or item.get("row_synonymy_verdict")
                                    or "EXPRESSES",
                "shipping_gate_verdict": item.get("shipping_gate_verdict"),
                "manifest_source": args.manifest_source,
                "pkg": Path(output_path).parts[-2],
                "file": "lints/" + output_path.split("/")[-2] + "/" + Path(output_path).name,
            })
        full_manifest = {
            "zlint_v3": str(ZLINT),
            "source_manifest": str(manifest_src),
            "manifest_source": args.manifest_source,
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
        src_dir = manifest_src.parent / "synonymous_lints"
        if not src_dir.exists():
            sys.exit(f"[error] lint source dir not found: {src_dir}")

        removed = 0
        for old in (ZLINT / "lints").glob("*/lint_cicasgen_*.go"):
            old.unlink()
            removed += 1
        print(f"[inject] removed {removed} stale cicasgen lint files")

        allowed = {
            (entry["pkg"], Path(entry["file"]).name)
            for entry in zlint_entries
        }
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
                if (pkg, f.name) not in allowed:
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
        result = subprocess.run(
            ["go", "build", "-o", "zlint", "./cmd/zlint"],
            cwd=ZLINT,
            capture_output=True,
            text=True,
            timeout=600,
        )
        if result.returncode != 0:
            print(f"[build] binary FAILED (exit {result.returncode}):")
            print(result.stderr[-2000:])
            sys.exit(1)
        (ZLINT / "zlint").chmod(0o755)
        print("[build] OK")


if __name__ == "__main__":
    main()
