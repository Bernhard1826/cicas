"""codegen/detection/testdata_oracle.py — parse zlint's own *_test.go files into a
ground-truth map of certificate intent.

zlint ships, for almost every lint, a `*_test.go` asserting the expected Status
of that lint on named testdata certs, e.g.

    inputPath := "subCertLocalityNameMustAppear.pem"
    expected  := lint.Error
    out := test.TestLint("e_sub_cert_locality_name_must_appear", inputPath)

That is an authoritative statement of intent: a cert some lint expects to
Error/Warn on is a KNOWN-BAD fixture; a cert only ever expected to Pass is a
POSITIVE (broadly valid) fixture. This is the static half of the triage oracle
(the runtime half — does any upstream lint actually fire — lives in scan.py).

Pure stdlib; no build, no DB.
"""
from __future__ import annotations

import re
from pathlib import Path

# .../codegen/detection/testdata_oracle.py -> parents[5] == cicas_backend/
_BACKEND = Path(__file__).resolve().parents[5]
DEFAULT_LINTS = _BACKEND / "zlint" / "v3" / "lints"

_FUNC_SPLIT = re.compile(r"\bfunc\s+Test\w*\s*\(", re.M)
_INPUTPATH = re.compile(r'inputPath\s*(?::=|=)\s*"([^"]+)"')
_EXPECTED = re.compile(r'expected\s*(?::=|=)\s*lint\.(\w+)')
_TESTLINT = re.compile(r'test\.TestLint\w*\(\s*"([^"]+)"\s*,\s*([^)]+)\)')
_STR_ARG = re.compile(r'^"([^"]+)"$')
_NONPASS_NAMES = {"Error", "Warn", "Fatal"}


def parse_test_file(path: Path) -> list[tuple[str, str, str]]:
    """Return [(lint_name, cert_file, expected_status), ...] from one *_test.go.
    Splits into per-Test-func chunks and pairs each TestLint(lint, arg) with the
    nearest inputPath / expected assignment (or an inline string arg)."""
    text = path.read_text(errors="ignore")
    out = []
    for chunk in _FUNC_SPLIT.split(text):
        calls = _TESTLINT.findall(chunk)
        if not calls:
            continue
        inpaths = _INPUTPATH.findall(chunk)
        exps = _EXPECTED.findall(chunk)
        default_cert = inpaths[0] if inpaths else None
        default_exp = exps[0] if exps else None
        for lint_name, arg in calls:
            m = _STR_ARG.match(arg.strip())
            cert = m.group(1) if m else default_cert
            if cert:
                out.append((lint_name, cert, default_exp or "Pass"))
    return out


def build_intent_map(lints_dir: Path = DEFAULT_LINTS) -> dict:
    """{cert: {"nonpass": {lint: status}, "pass": [lints]}} over all test files.
    Includes a "_meta" key with file/assertion counts."""
    intent: dict = {}
    n_files = n_assert = 0
    for tf in Path(lints_dir).glob("*/*_test.go"):
        n_files += 1
        for lint_name, cert, exp in parse_test_file(tf):
            n_assert += 1
            slot = intent.setdefault(cert, {"nonpass": {}, "pass": []})
            if exp in _NONPASS_NAMES:
                slot["nonpass"][lint_name] = exp
            elif exp == "Pass":
                slot["pass"].append(lint_name)
    intent["_meta"] = {"test_files": n_files, "assertions": n_assert}
    return intent
