#!/usr/bin/env python3
"""
Collect recently-logged certificates from a public CT log into a flat PEM corpus.

Sibling to collect_tranco_tls.py: an input builder for
experiments/new_lint_corpus_scan, not part of the cert_detection paper gate.

Unlike the Tranco TLS collector (leaf certs from live :443 handshakes), this
pulls entries directly from a CT log's get-entries endpoint near the tree tip,
so it captures *recently issued* certificates including precertificates and a
broader mix of issuers/CA hierarchies. RFC 6962 wire structures are parsed
inline (no extra deps): MerkleTreeLeaf -> TimestampedEntry -> {X509 cert |
Precert TBS}, with the full precertificate and chain recovered from extra_data.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import urlopen, Request

from cryptography import x509
from cryptography.hazmat.primitives import serialization


HERE = Path(__file__).resolve().parent
DEFAULT_INPUTS = HERE / "inputs"
# A Google-operated log that is directly reachable from this host.
DEFAULT_LOG = "https://ct.googleapis.com/logs/us1/argon2025h2/ct/v1/"


def _get(url: str, timeout: float) -> dict:
    req = Request(url, headers={"User-Agent": "cicas-ct-collector/1.0"})
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def _read_u24(buf: bytes, off: int) -> tuple[int, int]:
    if off + 3 > len(buf):
        raise ValueError("u24 read past end")
    n = (buf[off] << 16) | (buf[off + 1] << 8) | buf[off + 2]
    return n, off + 3


def _read_asn1_cert(buf: bytes, off: int) -> tuple[bytes, int]:
    ln, off = _read_u24(buf, off)
    end = off + ln
    if end > len(buf):
        raise ValueError("ASN.1Cert read past end")
    return buf[off:end], end


def _read_cert_vector(buf: bytes, off: int) -> list[bytes]:
    if off >= len(buf):
        return []
    total, off = _read_u24(buf, off)
    end = min(off + total, len(buf))
    certs = []
    while off < end:
        cert, off = _read_asn1_cert(buf, off)
        certs.append(cert)
    return certs


def _read_repeated_certs(buf: bytes, off: int) -> list[bytes]:
    certs = []
    while off < len(buf):
        cert, off = _read_asn1_cert(buf, off)
        certs.append(cert)
    return certs


def _chain_from_x509_extra(extra: bytes) -> list[bytes]:
    try:
        return _read_cert_vector(extra, 0)
    except Exception:
        try:
            return _read_repeated_certs(extra, 0)
        except Exception:
            return []


def _chain_from_precert_extra(extra: bytes) -> tuple[bytes, list[bytes]]:
    pre_cert, off = _read_asn1_cert(extra, 0)
    try:
        chain = _read_cert_vector(extra, off)
    except Exception:
        try:
            chain = _read_repeated_certs(extra, off)
        except Exception:
            chain = []
    return pre_cert, chain


def _parse_entry(leaf_input_b64: str, extra_b64: str) -> tuple[bytes, str, list[bytes]] | None:
    """Return (cert_der, entry_kind, chain_ders) or None if unparseable.

    entry_kind is 'x509' or 'precert'. For precerts we recover the full
    pre-certificate DER from extra_data (PrecertChainEntry.pre_certificate),
    which is a real issued certificate (carries the poison extension).
    """
    import base64

    leaf = base64.b64decode(leaf_input_b64)
    # MerkleTreeLeaf: version(1) leaf_type(1) TimestampedEntry
    # TimestampedEntry: timestamp(8) entry_type(2) ...
    if len(leaf) < 12:
        return None
    entry_type = struct.unpack(">H", leaf[10:12])[0]
    off = 12
    if entry_type == 0:  # x509_entry: ASN.1Cert (u24 len + DER)
        cert_der, _ = _read_asn1_cert(leaf, off)
        extra = base64.b64decode(extra_b64) if extra_b64 else b""
        return cert_der, "x509", _chain_from_x509_extra(extra)
    if entry_type == 1:  # precert_entry: leaf carries TBS only; full cert in extra_data
        extra = base64.b64decode(extra_b64)
        # PrecertChainEntry: ASN.1Cert pre_certificate, then certificate_chain.
        pre_cert, chain = _chain_from_precert_extra(extra)
        return pre_cert, "precert", chain
    return None


def _cert_meta(cert: x509.Certificate) -> dict:
    try:
        sans = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value
        dns_names = sans.get_values_for_type(x509.DNSName)
    except Exception:
        dns_names = []
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        is_ca = bool(bc.ca)
    except Exception:
        is_ca = None
    return {
        "cert_kind": "ca" if is_ca else "subscriber" if is_ca is False else "unknown",
        "basic_constraints_ca": is_ca,
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "self_issued": cert.subject == cert.issuer,
        "serial_number": format(cert.serial_number, "x"),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "san_dns": dns_names[:20],
    }


def _safe_label(s: str, max_len: int = 60) -> str:
    import re
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", (s or "").strip().lower())
    return (s[:max_len] or "cert").strip("._-") or "cert"


def _fetch_batch(log_url: str, start: int, end: int, timeout: float) -> list[dict]:
    url = f"{log_url}get-entries?start={start}&end={end}"
    last_err = None
    for attempt in range(4):
        try:
            data = _get(url, timeout)
            return data.get("entries", [])
        except Exception as e:  # transient 429/5xx/timeout
            last_err = e
            time.sleep(1.0 + attempt)
    raise RuntimeError(f"get-entries {start}-{end} failed: {last_err}")


def _load_seen_sha(certs_dir: Path) -> dict[str, str]:
    seen = {}
    for path in certs_dir.glob("*.pem"):
        try:
            der = x509.load_pem_x509_certificate(path.read_bytes()).public_bytes(
                serialization.Encoding.DER)
        except Exception:
            continue
        seen[hashlib.sha256(der).hexdigest()] = path.name
    return seen


def _write_cert_record(der: bytes, base: dict, *, cert_role: str, chain_index: int,
                       certs_dir: Path, seen_sha: dict[str, str]) -> tuple[dict, bool]:
    cert = x509.load_der_x509_certificate(der)
    pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    cmeta = _cert_meta(cert)
    sha = hashlib.sha256(der).hexdigest()
    rec = {
        **base,
        "cert_role": cert_role,
        "chain_index": chain_index,
        "sha256": sha,
        "status": "ok",
        **cmeta,
    }
    if sha in seen_sha:
        rec["duplicate_of"] = seen_sha[sha]
        return rec, False

    label = _safe_label(cmeta["san_dns"][0] if cmeta["san_dns"] else cmeta["subject"])
    fname = (f"{base['log_index']:010d}_{sha[:16]}_{base['entry_kind']}_"
             f"{chain_index:02d}_{cert_role}_{label}.pem")
    (certs_dir / fname).write_text(pem)
    seen_sha[sha] = fname
    rec["pem_file"] = fname
    return rec, True


def main():
    ap = argparse.ArgumentParser(description="Collect recent CT-log certs as PEM")
    ap.add_argument("--log-url", default=DEFAULT_LOG,
                    help="CT log base ending in /ct/v1/")
    ap.add_argument("--count", type=int, default=20000,
                    help="number of log entries to attempt to pull")
    ap.add_argument("--end-offset", type=int, default=1000,
                    help="start this many entries below the tree tip (avoid the "
                         "very newest unmerged region)")
    ap.add_argument("--batch", type=int, default=256,
                    help="entries per get-entries request (log may cap lower)")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--include-precerts", action="store_true", default=True)
    ap.add_argument("--no-precerts", dest="include_precerts", action="store_false")
    ap.add_argument("--include-chain", action="store_true", default=True,
                    help="save issuer chain certificates from CT extra_data")
    ap.add_argument("--no-chain", dest="include_chain", action="store_false")
    ap.add_argument("--inputs-root", type=Path, default=DEFAULT_INPUTS)
    ap.add_argument("--name", default=None)
    args = ap.parse_args()

    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    log_slug = _safe_label(args.log_url.split("/ct/v1")[0].split("/")[-1])
    name = args.name or f"ct_{log_slug}_{today}_n{args.count}"
    corpus_dir = args.inputs_root / name
    certs_dir = corpus_dir / "certs"
    certs_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = corpus_dir / "manifest.jsonl"
    meta_path = corpus_dir / "run_meta.json"

    sth = _get(f"{args.log_url}get-sth", args.timeout)
    tree_size = int(sth["tree_size"])
    end = tree_size - args.end_offset
    start = max(0, end - args.count)
    print(f"[ct] tree_size={tree_size} pulling [{start}, {end})", file=sys.stderr)

    meta_path.write_text(json.dumps({
        "started_at": datetime.now(timezone.utc).isoformat(),
        "source": "ct_log",
        "log_url": args.log_url,
        "tree_size_at_start": tree_size,
        "range_start": start,
        "range_end": end,
        "count_requested": args.count,
        "include_precerts": args.include_precerts,
        "include_chain": args.include_chain,
        "certs_dir": str(certs_dir),
        "manifest": str(manifest_path),
    }, indent=2))

    # Build batch ranges.
    ranges = []
    i = start
    while i < end:
        j = min(i + args.batch, end)
        ranges.append((i, j - 1))
        i = j

    seen_sha = _load_seen_sha(certs_dir)

    ok = dup = skipped = errors = rows_written = 0
    idx = 0
    with manifest_path.open("w") as manifest:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futs = {pool.submit(_fetch_batch, args.log_url, a, b, args.timeout): (a, b)
                    for a, b in ranges}
            for fut in as_completed(futs):
                a, b = futs[fut]
                try:
                    entries = fut.result()
                except Exception as e:
                    errors += 1
                    print(f"[ct] batch {a}-{b} error: {e}", file=sys.stderr)
                    continue
                for k, ent in enumerate(entries):
                    log_index = a + k
                    parsed = _parse_entry(ent.get("leaf_input", ""),
                                          ent.get("extra_data", ""))
                    if not parsed:
                        skipped += 1
                        continue
                    der, kind, chain_ders = parsed
                    cert_items: list[tuple[bytes, str, int]] = []
                    if kind != "precert" or args.include_precerts:
                        cert_items.append((der, f"logged_{kind}", 0))
                    elif not args.include_chain:
                        skipped += 1
                        continue
                    if args.include_chain:
                        cert_items.extend((chain_der, "chain", i)
                                          for i, chain_der in enumerate(chain_ders, 1))

                    base = {"log_index": log_index, "entry_kind": kind}
                    for item_der, cert_role, chain_index in cert_items:
                        try:
                            rec, is_unique = _write_cert_record(
                                item_der,
                                base,
                                cert_role=cert_role,
                                chain_index=chain_index,
                                certs_dir=certs_dir,
                                seen_sha=seen_sha,
                            )
                        except Exception:
                            skipped += 1
                            continue
                        if is_unique:
                            ok += 1
                        else:
                            dup += 1
                        manifest.write(json.dumps(rec, ensure_ascii=False) + "\n")
                        rows_written += 1
                idx += 1
                if idx % 20 == 0:
                    manifest.flush()
                    print(f"[ct] batches={idx}/{len(ranges)} unique={ok} dup={dup} "
                          f"rows={rows_written} skipped={skipped} err={errors}",
                          file=sys.stderr)

    print(json.dumps({
        "corpus_dir": str(corpus_dir),
        "certs_dir": str(certs_dir),
        "manifest": str(manifest_path),
        "unique_pems": ok,
        "duplicates": dup,
        "manifest_rows": rows_written,
        "skipped": skipped,
        "batch_errors": errors,
        "include_chain": args.include_chain,
        "scan_command": f"python3 experiments/cert_detection/run.py --certs {certs_dir}",
    }, indent=2))


if __name__ == "__main__":
    main()
