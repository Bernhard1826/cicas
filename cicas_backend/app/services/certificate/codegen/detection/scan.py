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


def scan_corpus(zlint: Path, certs_dir: Path, limit: int = 0) -> list[dict]:
    """Scan every *.pem under certs_dir with the built zlint binary.

    Returns one record per parseable cert:
      {"cert", "ours", "upstream", "ours_all"}
    where `ours`/`upstream` are non-pass findings only and `ours_all` keeps every
    cicasgen_ outcome (incl. pass/NA) so triage can compute firing fractions."""
    zlint, certs_dir = Path(zlint), Path(certs_dir)
    certs = sorted(certs_dir.glob("*.pem"))
    if limit:
        certs = certs[:limit]
    records = []
    for cert in certs:
        per_lint = scan_cert(zlint, cert)
        if per_lint is None:
            continue
        ours_np, up_np, ours_all = partition(per_lint)
        records.append({"cert": cert.name, "ours": ours_np,
                        "upstream": up_np, "ours_all": ours_all})
    return records
