"""codegen/detection/scan.py — run the BUILT zlint binary over a cert corpus and
split our cicasgen_ findings from upstream.

NOTE on why this is NOT a duplicate of atom_oracle.run_lints_over_certs: that
function builds a THROWAWAY go-run workspace containing only our generated lints
(for per-atom certification of *uncompiled* lints). Here we run the SHIPPED
binary built by inject_and_build.py, which carries the upstream zlint lints too —
we need those, because "did any upstream lint also flag this cert" is the
upstream-consensus half of the triage oracle. Different artifact, different job.
"""
from __future__ import annotations

import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .. import results_attribution as RA

# zlint result codes we treat as a reported problem.
NONPASS = {"error", "warn", "fatal"}


def scan_cert(zlint: Path, cert: Path) -> dict | None:
    """Run zlint over one cert; return its per-lint result dict, or None on a
    parse/crash failure. zlint exits 0 on a clean cert and non-zero when a lint
    fires; both carry JSON on stdout."""
    proc = subprocess.run([str(zlint), "-format", "pem", str(cert)],
                          capture_output=True, text=True)
    out = proc.stdout.strip()
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


def partition(per_lint: dict) -> tuple[dict, dict, dict]:
    """(ours_nonpass, upstream_nonpass, ours_all) from a zlint per-cert object.
    Flattens lint_name -> result string."""
    ours_np, up_np, ours_all = {}, {}, {}
    for name, rec in per_lint.items():
        res = (rec or {}).get("result", "")
        if RA.is_generated(name):
            ours_all[name] = res
            if res in NONPASS:
                ours_np[name] = res
        elif res in NONPASS:
            up_np[name] = res
    return ours_np, up_np, ours_all


def _scan_record(zlint: Path, cert: Path) -> dict | None:
    per_lint = scan_cert(zlint, cert)
    if per_lint is None:
        return None
    ours_np, up_np, ours_all = partition(per_lint)
    return {"cert": cert.name, "ours": ours_np,
            "upstream": up_np, "ours_all": ours_all}


def _progress(done: int, total: int, progress_every: int, label: str) -> None:
    if not progress_every:
        return
    if done == total or done % progress_every == 0:
        print(f"[scan] {label}: {done}/{total}", file=sys.stderr, flush=True)


def scan_corpus(zlint: Path, certs_dir: Path, limit: int = 0, workers: int = 1,
                progress_every: int = 0, label: str | None = None) -> list[dict]:
    """Scan every *.pem under certs_dir with the built zlint binary.

    Returns one record per parseable cert:
      {"cert", "ours", "upstream", "ours_all"}
    where `ours`/`upstream` are non-pass findings only and `ours_all` keeps every
    cicasgen_ outcome (incl. pass/NA) so triage can compute firing fractions."""
    zlint, certs_dir = Path(zlint), Path(certs_dir)
    certs = sorted(certs_dir.glob("*.pem"))
    if limit:
        certs = certs[:limit]
    total = len(certs)
    label = label or certs_dir.name
    workers = max(1, int(workers or 1))

    if workers == 1:
        records = []
        for i, cert in enumerate(certs, start=1):
            rec = _scan_record(zlint, cert)
            if rec is not None:
                records.append(rec)
            _progress(i, total, progress_every, label)
        return records

    ordered: list[tuple[int, dict]] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        future_to_index = {
            ex.submit(_scan_record, zlint, cert): i
            for i, cert in enumerate(certs)
        }
        for done, fut in enumerate(as_completed(future_to_index), start=1):
            rec = fut.result()
            if rec is not None:
                ordered.append((future_to_index[fut], rec))
            _progress(done, total, progress_every, label)
    return [rec for _, rec in sorted(ordered, key=lambda x: x[0])]
