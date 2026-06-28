"""codegen/detection/ — certificate detection as a SAIV gate.

Reusable MECHANISM for the closed loop "run our generated lints on real
certificates -> decide which findings are real -> blame the pipeline stage that
produced a spurious one". Per the project iron law, this logic lives in the
backend (a sibling of atom_oracle / results_attribution), and is *called* by the
driver scripts/system_metrics/cert_detection_loop.py — never reimplemented there.

  scan.py            run the built zlint binary over a cert corpus; split our
                     cicasgen_ findings from upstream (reuses results_attribution)
  testdata_oracle.py parse zlint's own *_test.go files into per-cert intent
  triage.py          REAL / SPURIOUS / UNCERTAIN per finding (testdata oracle +
                     upstream consensus; over-strictness == atom_oracle.sentinel)
  blame.py           attribute a spurious / over-broad lint to a pipeline stage
                     (automates the QUARANTINE dict in inject_and_build.py)
  verify_uncertain.py cert-grounded reverse-check that disambiguates UNCERTAIN
                     findings into CONFIRMED_REAL (genuine new lint) vs still-unsure
  independent_verify.py adversarial per-finding structural check (does NOT trust
                     triage): re-derives from openssl+DER whether each finding's
                     SPECIFIC defect is really present -> CONFIRMED / REFUTED.
"""
from . import (scan, testdata_oracle, triage, blame,          # noqa: F401
               verify_uncertain, independent_verify)
