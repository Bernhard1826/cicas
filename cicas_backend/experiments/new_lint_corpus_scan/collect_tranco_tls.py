#!/usr/bin/env python3
"""
Collect TLS certificates for Tranco domains into a flat PEM corpus.

This is intentionally an input builder for experiments/new_lint_corpus_scan, not
part of the cert_detection paper gate. By default this collector uses
`openssl s_client -showcerts` to save the peer leaf and any transmitted chain
certificates. Use --leaf-only to keep the legacy Python-ssl leaf-only behavior.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import socket
import ssl
import subprocess
import sys
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile
from urllib.request import urlopen

from cryptography import x509
from cryptography.hazmat.primitives import serialization


HERE = Path(__file__).resolve().parent
DEFAULT_INPUTS = HERE / "inputs"
DEFAULT_TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
PEM_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----\s+.*?-----END CERTIFICATE-----",
    re.S,
)


def _safe_label(s: str, max_len: int = 80) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", s.strip().lower())
    return (s[:max_len] or "domain").strip("._-") or "domain"


def _load_tranco_rows(csv_path: Path | None, url: str, limit: int, offset: int) -> list[tuple[int, str]]:
    if csv_path:
        return _read_rows(csv_path, limit, offset)

    with NamedTemporaryFile(suffix=".zip") as tmp:
        with urlopen(url, timeout=60) as resp:
            while True:
                chunk = resp.read(1024 * 1024)
                if not chunk:
                    break
                tmp.write(chunk)
        tmp.flush()
        with zipfile.ZipFile(tmp.name) as zf:
            csv_names = [n for n in zf.namelist() if n.endswith(".csv")]
            if not csv_names:
                raise RuntimeError("Tranco archive contains no CSV")
            with zf.open(csv_names[0]) as fh:
                text = (line.decode("utf-8", "replace") for line in fh)
                return _rows_from_iter(text, limit, offset)


def _read_rows(path: Path, limit: int, offset: int) -> list[tuple[int, str]]:
    with path.open(newline="") as f:
        return _rows_from_iter(f, limit, offset)


def _rows_from_iter(lines, limit: int, offset: int) -> list[tuple[int, str]]:
    out = []
    for row in csv.reader(lines):
        if len(row) < 2:
            continue
        try:
            rank = int(row[0])
        except ValueError:
            continue
        if rank <= offset:
            continue
        out.append((rank, row[1].strip().lower().rstrip(".")))
        if limit and len(out) >= limit:
            break
    return out


def _cert_record_from_der(der: bytes, *, cert_role: str, chain_index: int) -> dict:
    cert = x509.load_der_x509_certificate(der)
    pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns_names = sans.get_values_for_type(x509.DNSName)
    except Exception:
        dns_names = []
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        is_ca = bool(bc.ca)
    except Exception:
        is_ca = None
    meta = {
        "cert_role": cert_role,
        "chain_index": chain_index,
        "cert_kind": "ca" if is_ca else "subscriber" if is_ca is False else "unknown",
        "basic_constraints_ca": is_ca,
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "self_issued": cert.subject == cert.issuer,
        "serial_number": format(cert.serial_number, "x"),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "san_dns": dns_names,
    }
    return {
        "sha256": hashlib.sha256(der).hexdigest(),
        "pem": pem,
        **meta,
    }


def _der_from_pem_block(pem: bytes) -> bytes:
    cert = x509.load_pem_x509_certificate(pem)
    return cert.public_bytes(serialization.Encoding.DER)


def _fetch_leaf(host: str, timeout: float) -> tuple[bytes, str]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, 443), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
            if not der:
                raise RuntimeError("TLS peer returned no certificate")
            return der, tls.version() or ""


def _fetch_chain(host: str, timeout: float) -> tuple[list[bytes], str]:
    proc = subprocess.run(
        [
            "openssl",
            "s_client",
            "-connect",
            f"{host}:443",
            "-servername",
            host,
            "-showcerts",
        ],
        input=b"",
        capture_output=True,
        timeout=max(timeout + 3.0, timeout * 2.0),
    )
    output = proc.stdout + b"\n" + proc.stderr
    pems = PEM_RE.findall(output)
    if not pems:
        raise RuntimeError("openssl s_client returned no certificates")
    ders = [_der_from_pem_block(pem) for pem in pems]
    text = output.decode("utf-8", "replace")
    m = re.search(r"Protocol\s*:\s*([^\s]+)", text) or re.search(r"New,\s*([^,\s]+)", text)
    return ders, (m.group(1) if m else "")


def _collect_one(rank: int, domain: str, timeout: float, www_fallback: bool,
                 include_chain: bool) -> dict:
    candidates = [domain]
    if www_fallback and not domain.startswith("www."):
        candidates.append(f"www.{domain}")

    errors = []
    for host in candidates:
        try:
            if include_chain:
                ders, tls_version = _fetch_chain(host, timeout)
                method = "openssl_s_client_showcerts"
            else:
                der, tls_version = _fetch_leaf(host, timeout)
                ders = [der]
                method = "python_ssl_leaf"
            certs = [
                _cert_record_from_der(
                    der,
                    cert_role="leaf" if i == 0 else "chain",
                    chain_index=i,
                )
                for i, der in enumerate(ders)
            ]
            return {
                "rank": rank,
                "domain": domain,
                "sni": host,
                "status": "ok",
                "tls_version": tls_version,
                "collection_method": method,
                "certs": certs,
            }
        except Exception as e:
            errors.append(f"{host}: {type(e).__name__}: {e}")
    return {
        "rank": rank,
        "domain": domain,
        "status": "failed",
        "error": " | ".join(errors),
    }


def _load_done(manifest: Path) -> set[int]:
    done = set()
    if not manifest.exists():
        return done
    with manifest.open() as f:
        for line in f:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "rank" in rec:
                done.add(int(rec["rank"]))
    return done


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


def _write_cert_row(base: dict, cert_rec: dict, certs_dir: Path,
                    seen_sha: dict[str, str]) -> dict:
    pem = cert_rec["pem"]
    out = {**base, **{k: v for k, v in cert_rec.items() if k != "pem"}}
    sha = out["sha256"]
    role = out["cert_role"]
    if sha in seen_sha:
        out["duplicate_of"] = seen_sha[sha]
    else:
        name = (f"{out['rank']:07d}_{sha[:16]}_{_safe_label(out['sni'])}_"
                f"{out['chain_index']:02d}_{role}.pem")
        path = certs_dir / name
        path.write_text(pem)
        seen_sha[sha] = name
        out["pem_file"] = name
    return out


def _write_result(rec: dict, certs_dir: Path, manifest,
                  seen_sha: dict[str, str]) -> int:
    out = dict(rec)
    certs = out.pop("certs", [])
    if out.get("status") == "ok" and certs:
        rows = 0
        for cert_rec in certs:
            row = _write_cert_row(out, cert_rec, certs_dir, seen_sha)
            manifest.write(json.dumps(row, ensure_ascii=False) + "\n")
            rows += 1
        manifest.flush()
        return rows
    manifest.write(json.dumps(out, ensure_ascii=False) + "\n")
    manifest.flush()
    return 1


def main():
    ap = argparse.ArgumentParser(description="Collect Tranco TLS certs as PEM")
    ap.add_argument("--tranco-csv", type=Path, default=None,
                    help="local Tranco CSV; default downloads today's top-1m zip")
    ap.add_argument("--tranco-url", default=DEFAULT_TRANCO_URL)
    ap.add_argument("--limit", type=int, default=1000,
                    help="number of ranks to attempt; use 1000000 for full Tranco 1M")
    ap.add_argument("--offset", type=int, default=0,
                    help="skip ranks <= offset")
    ap.add_argument("--workers", type=int, default=64)
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--www-fallback", action="store_true",
                    help="try www.<domain> if the bare domain fails")
    ap.add_argument("--leaf-only", action="store_true",
                    help="legacy mode: save only the peer leaf certificate")
    ap.add_argument("--inputs-root", type=Path, default=DEFAULT_INPUTS)
    ap.add_argument("--name", default=None,
                    help="corpus name under inputs/; default includes date and limit")
    ap.add_argument("--resume", action="store_true",
                    help="append to an existing manifest and skip already attempted ranks")
    args = ap.parse_args()

    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    name = args.name or f"tranco_tls_{today}_top{args.limit}_offset{args.offset}"
    corpus_dir = args.inputs_root / name
    certs_dir = corpus_dir / "certs"
    certs_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = corpus_dir / "manifest.jsonl"
    meta_path = corpus_dir / "run_meta.json"

    rows = _load_tranco_rows(args.tranco_csv, args.tranco_url, args.limit, args.offset)
    done = _load_done(manifest_path) if args.resume else set()
    rows = [(rank, domain) for rank, domain in rows if rank not in done]

    seen_sha = _load_seen_sha(certs_dir)
    started_at = datetime.now(timezone.utc).isoformat()
    meta_path.write_text(json.dumps({
        "started_at": started_at,
        "source": "tranco_tls",
        "limit": args.limit,
        "offset": args.offset,
        "workers": args.workers,
        "timeout": args.timeout,
        "www_fallback": args.www_fallback,
        "include_tls_chain": not args.leaf_only,
        "chain_method": "openssl_s_client_showcerts" if not args.leaf_only else "python_ssl_leaf",
        "tranco_csv": str(args.tranco_csv) if args.tranco_csv else None,
        "tranco_url": args.tranco_url if not args.tranco_csv else None,
        "certs_dir": str(certs_dir),
        "manifest": str(manifest_path),
    }, indent=2))

    ok = failed = manifest_rows = 0
    mode = "a" if args.resume else "w"
    with manifest_path.open(mode) as manifest:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futs = [pool.submit(_collect_one, rank, domain, args.timeout,
                                args.www_fallback, not args.leaf_only)
                    for rank, domain in rows]
            for i, fut in enumerate(as_completed(futs), 1):
                rec = fut.result()
                if rec.get("status") == "ok":
                    ok += 1
                else:
                    failed += 1
                manifest_rows += _write_result(rec, certs_dir, manifest, seen_sha)
                if i % 100 == 0 or i == len(futs):
                    print(f"[collect] attempted={i}/{len(futs)} ok={ok} failed={failed}",
                          file=sys.stderr)

    print(json.dumps({
        "corpus_dir": str(corpus_dir),
        "certs_dir": str(certs_dir),
        "manifest": str(manifest_path),
        "attempted": len(rows),
        "ok": ok,
        "failed": failed,
        "manifest_rows": manifest_rows,
        "unique_pems": len(list(certs_dir.glob("*.pem"))),
        "include_tls_chain": not args.leaf_only,
        "scan_command": f"python3 experiments/cert_detection/run.py --certs {certs_dir}",
    }, indent=2))


if __name__ == "__main__":
    main()
