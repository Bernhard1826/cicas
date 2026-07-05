"""templates_v2 / render.py — deterministic DSL -> Go string emitter.

The emitter knows every ATOM/COMPOUND form and emits compilable Go using
zlint v3 + zcrypto APIs. Because vocab values map to verified Go
identifiers (vocab.FieldDef.go_expr) and the renderer never accepts
arbitrary strings as code, the emitted output is structurally correct
by construction.

Public entry points:
  render(node)              -> Go boolean expression string
  collect_imports(node)     -> set[str] of import paths needed
  used_vocab(node)          -> dict counting how many times each vocab
                                entry was referenced (for diagnostics)
"""
from __future__ import annotations

import re
from typing import Optional

from . import dsl, vocab as V


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

def render(node: dsl.Compound) -> str:
    """Render a Compound to a Go boolean expression."""
    return _emit(node, in_item=False, item_var=None)


def collect_imports(node: dsl.Compound) -> set[str]:
    """Walk and figure out which import paths the emission needs."""
    imps: set[str] = {
        "github.com/zmap/zcrypto/x509",        # always
        "github.com/zmap/zlint/v3/lint",       # always (caller wraps)
    }
    _walk_imports(node, imps)
    return imps


def used_vocab(node: dsl.Compound) -> dict:
    """For diagnostics: count vocab references in the tree."""
    out = {"oids": {}, "fields": {}, "ku_bits": {}, "eku_bits": {},
           "asn1_types": {}, "dates": {}}
    _walk_vocab(node, out)
    return out


# ---------------------------------------------------------------------
# Core emitter
# ---------------------------------------------------------------------

def _emit(n, *, in_item: bool, item_var) -> str:
    if isinstance(n, dsl.And):
        if len(n.parts) == 1:
            return _emit(n.parts[0], in_item=in_item, item_var=item_var)
        return "(" + " && ".join(_emit(p, in_item=in_item, item_var=item_var)
                                 for p in n.parts) + ")"
    if isinstance(n, dsl.Or):
        if len(n.parts) == 1:
            return _emit(n.parts[0], in_item=in_item, item_var=item_var)
        return "(" + " || ".join(_emit(p, in_item=in_item, item_var=item_var)
                                 for p in n.parts) + ")"
    if isinstance(n, dsl.Not):
        return "!(" + _emit(n.inner, in_item=in_item, item_var=item_var) + ")"
    if isinstance(n, dsl.When):
        # "when cond, main must hold" → (!cond) || main
        # (vacuously true when cond doesn't hold; equivalent to conditional body)
        c = _emit(n.cond, in_item=in_item, item_var=item_var)
        m = _emit(n.main, in_item=in_item, item_var=item_var)
        return f"(!({c})) || ({m})"

    # ----- atoms with no field reference -----
    if isinstance(n, dsl.IsCA):
        return "(c.IsCA && c.BasicConstraintsValid)"
    if isinstance(n, dsl.IsRootCA):
        return "(c.IsCA && c.SelfSigned)"
    if isinstance(n, dsl.IsSubCA):
        return "util.IsSubCA(c)"
    if isinstance(n, dsl.PathLenConstraintPresent):
        # pathLenConstraint present. zcrypto encodes (see x509.go MaxPathLen doc):
        #   ext absent           -> MaxPathLen==0,  MaxPathLenZero==false
        #   present, no pathLen  -> MaxPathLen==-1, MaxPathLenZero==false
        #   present, pathLen==0  -> MaxPathLen==0,  MaxPathLenZero==true
        #   present, pathLen==N>0-> MaxPathLen==N,  MaxPathLenZero==false
        # so present  <=>  (MaxPathLen > 0 || MaxPathLenZero). The old `>= 0`
        # wrongly treated an ABSENT extension (MaxPathLen==0) as present, firing
        # must-not-be-present lints on every cert without basicConstraints.
        return "(c.MaxPathLen > 0 || c.MaxPathLenZero)"
    if isinstance(n, dsl.IsServerCert):
        return "util.HasEKU(c, x509.ExtKeyUsageServerAuth)"
    if isinstance(n, dsl.IsSubscriberCert):
        return "(!c.IsCA)"
    if isinstance(n, dsl.IsEndEntity):
        return "(!c.IsCA)"  # end-entity = non-CA (same as IsSubscriberCert)

    if isinstance(n, dsl.CommonNameFromSAN):
        # subject commonName, if present, must equal one of the SAN dNSName /
        # iPAddress entries. Vacuously true when CN is empty. Mirrors zlint's
        # e_subject_common_name_not_from_san. No extra imports (net.IP.String()
        # is a method on the already-parsed field).
        return _iife_bool([
            "cn := c.Subject.CommonName",
            "if cn == \"\" { return true }",
            "for _, d := range c.DNSNames { if cn == d { return true } }",
            "for _, ip := range c.IPAddresses { if cn == ip.String() { return true } }",
            "return false",
        ])

    if isinstance(n, dsl.SubjectCommonNameFQDNOrWildcardPortionMatchesRegex):
        if n.pattern not in V.NAMED_REGEXES:
            raise dsl.DSLError(f"SubjectCommonNameFQDNOrWildcardPortionMatchesRegex: unknown named regex '{n.pattern}'")
        pat = _go_string(V.NAMED_REGEXES[n.pattern][0])
        return _iife_bool([
            "cn := c.Subject.CommonName",
            "if cn == \"\" { return true }",
            "if net.ParseIP(cn) != nil { return true }",
            "if !strings.Contains(cn, \".\") && !strings.HasPrefix(cn, \"*.\") { return true }",
            "target := cn",
            "if strings.HasPrefix(target, \"*.\") { target = target[2:] }",
            f"return regexp.MustCompile({pat}).MatchString(target)",
        ])

    if isinstance(n, dsl.SubjectCommonNameFQDNMatchesDNSNameSAN):
        return _iife_bool([
            "cn := c.Subject.CommonName",
            "if cn == \"\" { return true }",
            "if net.ParseIP(cn) != nil { return true }",
            "if !strings.Contains(cn, \".\") && !strings.HasPrefix(cn, \"*.\") { return true }",
            "for _, d := range c.DNSNames { if cn == d { return true } }",
            "return false",
        ])

    if isinstance(n, dsl.SigAlgMatchesTBSSignature):
        # Re-parse the cert DER and compare the signatureAlgorithm
        # AlgorithmIdentifier (in Certificate) byte-for-byte against the
        # signature AlgorithmIdentifier (in tbsCertificate). Mirrors zlint's
        # e_mismatched_signature_algorithm_identifier exactly. On any parse
        # failure, return true (don't flag) to avoid false positives.
        return _iife_bool([
            "input := cryptobyte.String(c.Raw)",
            "var cert cryptobyte.String",
            "if !input.ReadASN1(&cert, asn1.SEQUENCE) { return true }",
            "var tbsCert cryptobyte.String",
            "if !cert.ReadASN1(&tbsCert, asn1.SEQUENCE) { return true }",
            "var certSigAlg cryptobyte.String",
            "if !cert.ReadASN1(&certSigAlg, asn1.SEQUENCE) { return true }",
            "if !tbsCert.SkipOptionalASN1(asn1.Tag(0).Constructed().ContextSpecific()) { return true }",
            "if !tbsCert.SkipASN1(asn1.INTEGER) { return true }",
            "var tbsSigAlg cryptobyte.String",
            "if !tbsCert.ReadASN1(&tbsSigAlg, asn1.SEQUENCE) { return true }",
            "return bytes.Equal(certSigAlg, tbsSigAlg)",
        ])

    if isinstance(n, dsl.SignatureAlgorithmIdentifiersEqualHex):
        lit = _hex_literal(n.hex_lit)
        return _iife_bool([
            f"want := {lit}",
            "input := cryptobyte.String(c.Raw)",
            "var cert cryptobyte.String",
            "if !input.ReadASN1(&cert, asn1.SEQUENCE) { return false }",
            "var tbsCert cryptobyte.String",
            "if !cert.ReadASN1(&tbsCert, asn1.SEQUENCE) { return false }",
            "var certSigAlg cryptobyte.String",
            "if !cert.ReadASN1(&certSigAlg, asn1.SEQUENCE) { return false }",
            "if !tbsCert.SkipOptionalASN1(asn1.Tag(0).Constructed().ContextSpecific()) { return false }",
            "if !tbsCert.SkipASN1(asn1.INTEGER) { return false }",
            "var tbsSigAlg cryptobyte.String",
            "if !tbsCert.ReadASN1(&tbsSigAlg, asn1.SEQUENCE) { return false }",
            "return bytes.Equal(certSigAlg, want) && bytes.Equal(tbsSigAlg, want)",
        ])

    if isinstance(n, dsl.SPKIAlgorithmIdentifierEqualsHex):
        lit = _hex_literal(n.hex_lit)
        return _iife_bool([
            f"want := {lit}",
            "input := cryptobyte.String(c.RawSubjectPublicKeyInfo)",
            "var spki cryptobyte.String",
            "if !input.ReadASN1(&spki, asn1.SEQUENCE) { return false }",
            "var alg cryptobyte.String",
            "if !spki.ReadASN1(&alg, asn1.SEQUENCE) { return false }",
            "return bytes.Equal(alg, want)",
        ])

    if isinstance(n, dsl.NotAfterIsNoExpirySentinel):
        # RFC 5280 §4.1.2.5: the "no well-defined expiration date" marker is
        # notAfter == 99991231235959Z (GeneralizedTime). zcrypto parses it to
        # time.Time, so compare the UTC components directly.
        return _iife_bool([
            "_t := c.NotAfter.UTC()",
            "return _t.Year() == 9999 && _t.Month() == 12 && _t.Day() == 31 && "
            "_t.Hour() == 23 && _t.Minute() == 59 && _t.Second() == 59",
        ])

    if isinstance(n, dsl.ValidityUTCTimeValuesUseZulu):
        return _iife_bool([
            "type _tbsHead struct {",
            "\tVersion            int          `asn1:\"optional,explicit,tag:0,default:0\"`",
            "\tSerialNumber       asn1.RawValue",
            "\tSignatureAlgorithm asn1.RawValue",
            "\tIssuer             asn1.RawValue",
            "\tValidity           asn1.RawValue",
            "}",
            "var _t _tbsHead",
            "if _, _err := asn1.Unmarshal(c.RawTBSCertificate, &_t); _err != nil { return false }",
            "type _vy struct {",
            "\tNotBefore asn1.RawValue",
            "\tNotAfter  asn1.RawValue",
            "}",
            "var _v _vy",
            "if _, _err := asn1.Unmarshal(_t.Validity.FullBytes, &_v); _err != nil { return false }",
            "_check := func(_rv asn1.RawValue) bool {",
            "\tif _rv.Class == 0 && _rv.Tag == 23 {",
            "\t\treturn len(_rv.Bytes) > 0 && _rv.Bytes[len(_rv.Bytes)-1] == 'Z'",
            "\t}",
            "\treturn true",
            "}",
            "return _check(_v.NotBefore) && _check(_v.NotAfter)",
        ])

    # ----- extension presence / criticality -----
    if isinstance(n, dsl.HasAnyExtension):
        # "when extensions are used" → any extension present → version must be v3.
        # len(cert.Extensions) > 0 is the direct check. Generic, parameter-free.
        return "len(c.Extensions) > 0"
    if isinstance(n, dsl.ExtPresent):
        oid = V.OID_BY_NAME[n.oid].go_expr  # e.g. "util.AiaOID"
        return f"util.IsExtInCert(c, {oid})"
    if isinstance(n, dsl.ExtCritical):
        oid = V.OID_BY_NAME[n.oid].go_expr
        # "this extension MUST be critical" constrains HOW it is marked WHEN
        # present; it is vacuously satisfied when the extension is absent (a
        # separate presence rule covers that). Absent -> compliant, else critical.
        return (f"(util.GetExtFromCert(c, {oid}) == nil"
                f" || util.GetExtFromCert(c, {oid}).Critical)")
    if isinstance(n, dsl.ExtNotCritical):
        oid = V.OID_BY_NAME[n.oid].go_expr
        # vacuously satisfied when the extension is absent (see ExtCritical).
        return (f"(util.GetExtFromCert(c, {oid}) == nil"
                f" || !util.GetExtFromCert(c, {oid}).Critical)")
    if isinstance(n, dsl.ExtContentNonEmpty):
        # "MUST NOT be an empty sequence": the extension's parsed content has >=1
        # element. Sound only where zcrypto exposes the content. nameConstraints =
        # sum of all 16 permitted/excluded subtree lists > 0 (an empty NC SEQUENCE
        # parses to all-empty lists). Other OIDs: refuse (content unreachable).
        if n.oid in ("NameConstOID", "NameConstraintsOID"):
            _nc = ["PermittedDNSNames", "ExcludedDNSNames", "PermittedEmailAddresses",
                   "ExcludedEmailAddresses", "PermittedURIs", "ExcludedURIs",
                   "PermittedIPAddresses", "ExcludedIPAddresses", "PermittedDirectoryNames",
                   "ExcludedDirectoryNames", "PermittedEdiPartyNames", "ExcludedEdiPartyNames",
                   "PermittedRegisteredIDs", "ExcludedRegisteredIDs", "PermittedX400Addresses",
                   "ExcludedX400Addresses"]
            return "(" + "+".join(f"len(c.{x})" for x in _nc) + ") > 0"
        raise dsl.DSLError(
            f"ExtContentNonEmpty: no zcrypto content accessor for OID {n.oid!r} "
            f"(content-emptiness unreachable; honest residual)")

    # ----- generic extension-level checks -----
    if isinstance(n, dsl.ExtensionURISchemeNotInSet):
        # For each extension, walk its raw DER SEQUENCE looking for
        # GeneralName CHOICE items with context tag 6 (uniformResourceIdentifier).
        # Check that none of the URI values starts with any forbidden scheme.
        # Fail-closed: if an extension fails to parse, assume violation.
        scheme_lit = "[]string{" + ",".join(_go_string(s) for s in n.schemes) + "}"
        return _iife_bool([
            f"_schemes := {scheme_lit}",
            "for _, ext := range c.Extensions {",
            "    var _seq asn1.RawValue",
            "    if _, err := asn1.Unmarshal(ext.Value, &_seq); err != nil { continue }",
            "    _rest := _seq.Bytes",
            "    for len(_rest) > 0 {",
            "        var _v asn1.RawValue",
            "        _next, err := asn1.Unmarshal(_rest, &_v)",
            "        if err != nil { break }",
            "        _rest = _next",
            "        if _v.Class == asn1.ClassContextSpecific && _v.Tag == 6 {",
            "            for _, _s := range _schemes {",
            "                if len(_v.Bytes) > len(_s) &&",
            "                   string(_v.Bytes[:len(_s)+1]) == _s+\":\" {",
            "                    return false }",
            "            }",
            "        }",
            "    }",
            "}",
            "return true",
        ])

    # ----- key usage bits -----
    if isinstance(n, dsl.KeyUsageHas):
        bit = V.KU_BY_NAME[n.bit].go_expr  # e.g. x509.KeyUsageDigitalSignature
        return f"((c.KeyUsage & {bit}) != 0)"
    if isinstance(n, dsl.KeyUsageOnlyHasBitsInSet):
        bit_exprs = []
        for bit_name in n.bits:
            norm = _norm_bit_name(str(bit_name))
            if norm not in V.KU_BY_NAME:
                raise dsl.DSLError(f"KeyUsageOnlyHasBitsInSet: unknown KEY_USAGE_BIT '{bit_name}'")
            bit_exprs.append(V.KU_BY_NAME[norm].go_expr)
        mask = " | ".join(bit_exprs) if bit_exprs else "0"
        return f"((c.KeyUsage & ^({mask})) == 0)"
    if isinstance(n, dsl.ExtKeyUsageHas):
        bit = V.EKU_BY_NAME[n.bit].go_expr
        return f"util.HasEKU(c, {bit})"
    if isinstance(n, dsl.ExtKeyUsageOnlyHasUsagesInSet):
        return _emit_eku_only_allowed(n.bits)

    # ----- field equality / set / regex / non-empty -----
    if isinstance(n, dsl.FieldEq):
        f = _lookup_field(n.field)
        rhs = _go_literal(n.value, f.semantic)
        return _emit_field_eq(f, rhs)
    if isinstance(n, dsl.FieldNonEmpty):
        return _emit_field_nonempty(_lookup_field(n.field))
    if isinstance(n, dsl.FieldEmpty):
        return "!(" + _emit_field_nonempty(_lookup_field(n.field)) + ")"
    if isinstance(n, dsl.FieldMatchesRegex):
        if n.field == "_item" and in_item and item_var is not None:
            if n.pattern not in V.NAMED_REGEXES:
                raise dsl.DSLError(f"FieldMatchesRegex: unknown named regex '{n.pattern}'")
            pat = _go_string(V.NAMED_REGEXES[n.pattern][0])
            return f"regexp.MustCompile({pat}).MatchString({item_var})"
        f = _lookup_field(n.field)
        return _emit_field_regex(f, n.pattern)
    if isinstance(n, dsl.FieldInSet):
        f = _lookup_field(n.field)
        return _emit_field_in_set(f, n.values, negate=False)
    if isinstance(n, dsl.FieldNotInSet):
        f = _lookup_field(n.field)
        return _emit_field_in_set(f, n.values, negate=True)
    if isinstance(n, dsl.FieldLenInRange):
        f = _lookup_field(n.field)
        return _emit_field_len_range(f, n.lo, n.hi)
    if isinstance(n, dsl.FieldNumericInRange):
        f = _lookup_field(n.field)
        return _emit_field_numeric_range(f, n.lo, n.hi)

    # ----- serial number -----
    if isinstance(n, dsl.SerialNumberPositive):
        # serialNumber > 0: matches pattern used in existing generated lints
        # Rendered as: c.SerialNumber != nil && c.SerialNumber.Cmp(big.NewInt(0)) > 0
        return "(c.SerialNumber != nil && c.SerialNumber.Cmp(big.NewInt(0)) > 0)"
    if isinstance(n, dsl.SerialNumberOctetLengthInRange):
        # serialNumber byte length in [lo, hi]
        # Rendered as: len(c.SerialNumber.Bytes()) >= lo && len(c.SerialNumber.Bytes()) <= hi
        lo, hi = n.lo, n.hi
        return (f"(len(c.SerialNumber.Bytes()) >= {lo} && "
                f"len(c.SerialNumber.Bytes()) <= {hi})")
    if isinstance(n, dsl.SerialNumberDERSignBitZero):
        return _iife_bool([
            "type _tbsHead struct {",
            "\tVersion            int          `asn1:\"optional,explicit,tag:0,default:0\"`",
            "\tSerialNumber       asn1.RawValue",
            "}",
            "var _t _tbsHead",
            "if _, _err := asn1.Unmarshal(c.RawTBSCertificate, &_t); _err != nil { return false }",
            "if _t.SerialNumber.Class != 0 || _t.SerialNumber.Tag != asn1.TagInteger { return false }",
            "if len(_t.SerialNumber.Bytes) == 0 { return false }",
            "return (_t.SerialNumber.Bytes[0] & 0x80) == 0",
        ])

    if isinstance(n, dsl.FieldEncodedAs):
        if n.field in ("Subject", "Issuer", "subject", "issuer"):
            return _emit_dn_values_encoded_as(n.field, n.types)
        f = _lookup_field(n.field)
        return _emit_field_encoded_as(f, n.types)
    if isinstance(n, dsl.DNDirectoryStringValuesEncodedAs):
        return _emit_dn_directorystring_encoded_as(n.dn, n.types)
    if isinstance(n, dsl.FieldCount):
        f = _lookup_field(n.field)
        return _emit_field_count(f, n.lo, n.hi)

    # ----- date -----
    if isinstance(n, dsl.DateAfter):
        later   = V.DATE_BY_NAME[n.later].go_expr
        earlier = V.DATE_BY_NAME[n.earlier].go_expr
        return f"{later}.After({earlier})"

    # ----- list iteration -----
    if isinstance(n, dsl.ListAllMatch):
        return _emit_list_iter(n.list_field, n.predicate, semantic="all")
    if isinstance(n, dsl.ListAnyMatch):
        return _emit_list_iter(n.list_field, n.predicate, semantic="any")
    if isinstance(n, dsl.ListUnique):
        f = _lookup_field(n.list_field)
        return _emit_list_unique(f)

    # ----- in-item predicates -----
    if isinstance(n, dsl.ItemMatchesRegex):
        if not in_item or item_var is None:
            raise dsl.DSLError("ItemMatchesRegex outside list iter")
        if n.pattern not in V.NAMED_REGEXES:
            raise dsl.DSLError(f"ItemMatchesRegex: unknown named regex '{n.pattern}'")
        pat = _go_string(V.NAMED_REGEXES[n.pattern][0])
        return f"regexp.MustCompile({pat}).MatchString({item_var})"
    if isinstance(n, dsl.ItemInSet):
        if not in_item or item_var is None:
            raise dsl.DSLError("ItemInSet outside list iter")
        lits = ", ".join(_go_literal(v, "string") for v in n.values)
        return _iife_bool([
            f"for _, _x := range []string{{{lits}}} {{",
            f"\tif _x == {item_var} {{ return true }}",
            f"}}",
            f"return false",
        ])
    if isinstance(n, dsl.ItemEq):
        if (not in_item or item_var is None) and item_var != "_ip":
            raise dsl.DSLError("ItemEq outside list iter")
        return f"({item_var} == {_go_literal(n.value, 'string')})"
    if isinstance(n, dsl.ItemLenIn):
        if not in_item:
            raise dsl.DSLError("ItemLenIn only valid inside list iter")
        ok = " || ".join(f"len({item_var}) == {c}" for c in n.counts)
        return f"({ok})"
    if isinstance(n, dsl.ItemNotMatchesRegex):
        if not in_item or item_var is None:
            raise dsl.DSLError("ItemNotMatchesRegex outside list iter")
        if n.pattern not in V.NAMED_REGEXES:
            raise dsl.DSLError(f"ItemNotMatchesRegex: unknown named regex '{n.pattern}'")
        pat = _go_string(V.NAMED_REGEXES[n.pattern][0])
        return f"!regexp.MustCompile({pat}).MatchString({item_var})"

    if isinstance(n, dsl.BytesEq):
        a = V.lookup_anyfield(n.field_a)
        b = V.lookup_anyfield(n.field_b)
        return f"bytes.Equal({a.go_expr}, {b.go_expr})"
    if isinstance(n, dsl.IPListAllOctetCount):
        f = V.lookup_anyfield(n.field)
        return _iife_bool([
            f"for _, _ip := range {f.go_expr} {{",
            f"\tif len(_ip) != {n.count} {{ return false }}",
            f"}}",
            f"return true",
        ])
    if isinstance(n, dsl.IPListVersionAllOctetCount):
        f = V.lookup_anyfield(n.field)
        if n.version == 4:
            return _iife_bool([
                f"for _, _ip := range {f.go_expr} {{",
                "\tif _ip.To4() == nil { continue }",
                f"\tif len(_ip) != {n.count} {{ return false }}",
                "}",
                "return true",
            ])
        if n.version == 6:
            return _iife_bool([
                f"for _, _ip := range {f.go_expr} {{",
                "\tif _ip.To4() != nil { continue }",
                f"\tif len(_ip) != {n.count} {{ return false }}",
                "}",
                "return true",
            ])
        raise dsl.DSLError(f"IPListVersionAllOctetCount: unsupported version {n.version}")
    if isinstance(n, dsl.OidListContains):
        f = V.lookup_anyfield(n.field)
        ge = V.OID_BY_NAME[n.oid].go_expr
        if ge.startswith("asn1.ObjectIdentifier{"):
            # inline-literal OID (EXTRA_OIDS): compare by dotted string so we never
            # mix stdlib vs zcrypto asn1.ObjectIdentifier types (zcrypto's .Equal
            # rejects the stdlib literal). .String() on the zcrypto OID gives the
            # dotted form. No asn1 import needed. (Extract digits from INSIDE the
            # braces only — "asn1" itself contains a digit.)
            import re as _re
            dotted = ".".join(_re.findall(r"\d+", ge[ge.find("{"):]))
            return _iife_bool([
                f"for _, _o := range {f.go_expr} {{",
                f'\tif _o.String() == "{dotted}" {{ return true }}',
                f"}}",
                f"return false",
            ])
        return _iife_bool([
            f"for _, _o := range {f.go_expr} {{",
            f"\tif _o.Equal({ge}) {{ return true }}",
            f"}}",
            f"return false",
        ])

    if isinstance(n, dsl.OidListCountInSet):
        f = V.lookup_anyfield(n.field)
        import re as _re
        conds = []
        for o in n.allowed_oids:
            ge = V.OID_BY_NAME[o].go_expr
            if ge.startswith("asn1.ObjectIdentifier{"):
                dotted = ".".join(_re.findall(r"\d+", ge[ge.find("{"):]))
                conds.append(f'_o.String() == "{dotted}"')
            else:
                conds.append(f"_o.Equal({ge})")
        cond = " || ".join(conds) if conds else "false"
        hi = "math.MaxInt" if n.hi == "MAX_INT" else str(n.hi)
        return _iife_bool([
            "_n := 0",
            f"for _, _o := range {f.go_expr} {{",
            f"\tif {cond} {{ _n++ }}",
            "}",
            f"return _n >= {n.lo} && _n <= {hi}",
        ])

    if isinstance(n, dsl.DateBefore):
        a = _emit_date_ref(n.earlier)
        b = _emit_date_ref(n.later)
        return f"({a}.Before({b}))"
    if isinstance(n, dsl.BytesEqualsHex):
        f = V.lookup_anyfield(n.field)
        lit = _hex_literal(n.hex_lit)
        return f"bytes.Equal({f.go_expr}, {lit})"
    if isinstance(n, dsl.BytesContainsHex):
        f = V.lookup_anyfield(n.field)
        lit = _hex_literal(n.hex_lit)
        return f"bytes.Contains({f.go_expr}, {lit})"
    if isinstance(n, dsl.PublicKeyAlgorithmIs):
        return f"(c.PublicKeyAlgorithm == x509.{n.algorithm})"
    if isinstance(n, dsl.RSAModulusBitsInRange):
        hi = "math.MaxInt" if (n.hi == "MAX_INT" or (isinstance(n.hi, int) and n.hi > (1 << 62))) else str(n.hi)
        return _iife_bool([
            "_k, _ok := c.PublicKey.(*rsa.PublicKey)",
            "if !_ok { return true }",   # rule scopes to RSA keys; vacuous otherwise
            "_b := _k.N.BitLen()",
            f"return _b >= {n.lo} && _b <= {hi}",
        ])
    if isinstance(n, dsl.RSAPublicExponentInRange):
        # zcrypto's rsa.PublicKey.E is *big.Int (not stdlib's int) -> big.Int Cmp,
        # which also handles huge bounds (e.g. exponent <= 2^256-1) faithfully.
        def _bigexpr(v):
            return (f"big.NewInt({v})" if isinstance(v, int) and abs(v) <= (1 << 62)
                    else 'func() *big.Int { _v, _ := new(big.Int).SetString("'
                         + str(int(v)) + '", 10); return _v }()')
        conds = [f"_k.E.Cmp({_bigexpr(n.lo)}) >= 0"]
        if n.hi != "MAX_INT":
            conds.append(f"_k.E.Cmp({_bigexpr(n.hi)}) <= 0")
        return _iife_bool([
            "_k, _ok := c.PublicKey.(*rsa.PublicKey)",
            "if !_ok { return true }",
            "return " + " && ".join(conds),
        ])
    if isinstance(n, dsl.DNEmpty):
        # empty SEQUENCE: every pkix.Name slice/string field is empty + no extra entries
        return f"(len(c.{n.holder}.Names) == 0 && len(c.{n.holder}.ExtraNames) == 0)"

    if isinstance(n, dsl.RDNCountInRange):
        hi = "math.MaxInt" if (n.hi == "MAX_INT" or (isinstance(n.hi, int) and n.hi > (1 << 62))) else str(n.hi)
        return _iife_bool([
            f"_n := len(c.{n.holder}.Names)",
            f"return _n >= {n.lo} && _n <= {hi}",
        ])
    if isinstance(n, dsl.DNHasRDNSequence):
        raw = f"c.Raw{n.holder}"
        return _iife_bool([
            f"if len({raw}) == 0 {{ return false }}",
            "var _outer asn1.RawValue",
            f"_tail, _e := asn1.Unmarshal({raw}, &_outer)",
            "if _e != nil || len(_tail) != 0 { return false }",
            "if _outer.Class != 0 || _outer.Tag != asn1.TagSequence || !_outer.IsCompound { return false }",
            "_rest := _outer.Bytes",
            "for len(_rest) > 0 {",
            "\tvar _rdn asn1.RawValue",
            "\t_rest, _e = asn1.Unmarshal(_rest, &_rdn)",
            "\tif _e != nil { return false }",
            "\tif _rdn.Class != 0 || _rdn.Tag != asn1.TagSet || !_rdn.IsCompound { return false }",
            "}",
            "return true",
        ])
    if isinstance(n, dsl.RDNHasSingleAttribute):
        raw = f"c.Raw{n.holder}"
        return _iife_bool([
            f"if len({raw}) == 0 {{ return true }}",
            "var _outer asn1.RawValue",
            f"if _, _e := asn1.Unmarshal({raw}, &_outer); _e != nil {{ return false }}",
            "_rest := _outer.Bytes",
            "for len(_rest) > 0 {",
            "\tvar _rdn asn1.RawValue",
            "\tvar _e error",
            "\t_rest, _e = asn1.Unmarshal(_rest, &_rdn)",
            "\tif _e != nil { return false }",
            "\t_inner := _rdn.Bytes",
            "\t_count := 0",
            "\tfor len(_inner) > 0 {",
            "\t\tvar _atv asn1.RawValue",
            "\t\t_inner, _e = asn1.Unmarshal(_inner, &_atv)",
            "\t\tif _e != nil { return false }",
            "\t\t_count++",
            "\t}",
            "\tif _count != 1 { return false }",
            "}",
            "return true",
        ])
    if isinstance(n, dsl.RDNSequenceHasCountryBefore):
        raw = f"c.Raw{n.holder}"
        return _iife_bool([
            f"if len({raw}) == 0 {{ return true }}",
            "var _outer asn1.RawValue",
            f"if _, _e := asn1.Unmarshal({raw}, &_outer); _e != nil {{ return false }}",
            "var _cIdx, _sIdx = -1, -1",
            "_rest := _outer.Bytes",
            "_idx := 0",
            "for len(_rest) > 0 {",
            "\tvar _rdn asn1.RawValue",
            "\tvar _e error",
            "\t_rest, _e = asn1.Unmarshal(_rest, &_rdn)",
            "\tif _e != nil { return false }",
            "\t_inner := _rdn.Bytes",
            "\tfor len(_inner) > 0 {",
            "\t\tvar _atv struct { Type asn1.ObjectIdentifier; Value asn1.RawValue }",
            "\t\t_inner, _e = asn1.Unmarshal(_inner, &_atv)",
            "\t\tif _e != nil { return false }",
            "\t\t_oid := _atv.Type.String()",
            '\t\tif _oid == "2.5.4.6" && _cIdx < 0 { _cIdx = _idx }',
            '\t\tif _oid == "2.5.4.8" && _sIdx < 0 { _sIdx = _idx }',
            "\t}",
            "\t_idx++",
            "}",
            "\treturn _cIdx < 0 || _sIdx < 0 || _cIdx < _sIdx",
        ])

    if isinstance(n, dsl.ExtRawValueEqualsHex):
        oid = V.OID_BY_NAME[n.oid].go_expr
        lit = _hex_literal(n.hex_lit)
        return _iife_bool([
            f"_e := util.GetExtFromCert(c, {oid})",
            f"if _e == nil {{ return false }}",
            f"return bytes.Equal(_e.Value, {lit})",
        ])
    if isinstance(n, dsl.ExtRawValueContainsHex):
        oid = V.OID_BY_NAME[n.oid].go_expr
        lit = _hex_literal(n.hex_lit)
        return _iife_bool([
            f"_e := util.GetExtFromCert(c, {oid})",
            f"if _e == nil {{ return false }}",
            f"return bytes.Contains(_e.Value, {lit})",
        ])

    if isinstance(n, dsl.BasicConstraintsCAFalseEncodedAsEmptySequence):
        oid = V.OID_BY_NAME["BasicConstOID"].go_expr
        return _iife_bool([
            f"_e := util.GetExtFromCert(c, {oid})",
            "if _e == nil { return true }",
            "if bytes.Equal(_e.Value, []byte{0x30, 0x00}) { return true }",
            "var _seq asn1.RawValue",
            "if _, _err := asn1.Unmarshal(_e.Value, &_seq); _err != nil { return false }",
            "_rest := _seq.Bytes",
            "if len(_rest) == 0 { return true }",
            "var _ca asn1.RawValue",
            "if _, _err := asn1.Unmarshal(_rest, &_ca); _err != nil { return false }",
            "if _ca.Class == 0 && _ca.Tag == asn1.TagBoolean && len(_ca.Bytes) == 1 && _ca.Bytes[0] == 0x00 { return false }",
            "return true",
        ])

    if isinstance(n, dsl.ExtSubfieldPresent):
        oid = V.OID_BY_NAME[n.oid].go_expr
        if n.path == "":
            # Top-level: extnValue is a SEQUENCE whose members are context-tagged
            # (e.g. AuthorityKeyIdentifier: keyIdentifier[0], authorityCertIssuer[1],
            # authorityCertSerialNumber[2]). Decode as SEQUENCE OF RawValue and test
            # for a member carrying the target context tag. Fail-closed: extension
            # absent or undecodable ⇒ false (never a false positive).
            return _iife_bool([
                f"_e := util.GetExtFromCert(c, {oid})",
                "if _e == nil { return false }",
                "var _members []asn1.RawValue",
                "if _, _err := asn1.Unmarshal(_e.Value, &_members); _err != nil { return false }",
                "for _, _m := range _members {",
                f"\tif _m.Class == asn1.ClassContextSpecific && _m.Tag == {n.tag} {{ return true }}",
                "}",
                "return false",
            ])
        if n.path == "generalsubtree":
            # nameConstraints: extnValue SEQUENCE { permittedSubtrees [0] OPTIONAL,
            # excludedSubtrees [1] OPTIONAL }, each an implicitly-tagged SEQUENCE OF
            # GeneralSubtree { base GeneralName, minimum [0] DEFAULT 0, maximum [1]
            # OPTIONAL }. True iff ANY GeneralSubtree carries the target bound tag.
            # The base GeneralName is itself context-tagged (CHOICE tags 0..8) and
            # would collide with minimum[0]/maximum[1], so we SKIP the first element
            # (base) and test only the trailing bound elements. minimum==0 is
            # DER-DEFAULT-omitted, so a present [0]/[1] is an explicit bound.
            return _iife_bool([
                f"_e := util.GetExtFromCert(c, {oid})",
                "if _e == nil { return false }",
                "var _wrappers []asn1.RawValue",
                "if _, _err := asn1.Unmarshal(_e.Value, &_wrappers); _err != nil { return false }",
                "for _, _w := range _wrappers {",
                "\tif _w.Class != asn1.ClassContextSpecific { continue }",
                "\t_rest := _w.Bytes",
                "\tfor len(_rest) > 0 {",
                "\t\tvar _gs asn1.RawValue",
                "\t\t_r, _err := asn1.Unmarshal(_rest, &_gs)",
                "\t\tif _err != nil { break }",
                "\t\t_rest = _r",
                "\t\tvar _parts []asn1.RawValue",
                "\t\tif _, _e2 := asn1.Unmarshal(_gs.FullBytes, &_parts); _e2 != nil { continue }",
                "\t\tfor _i := 1; _i < len(_parts); _i++ {",
                f"\t\t\tif _parts[_i].Class == asn1.ClassContextSpecific && _parts[_i].Tag == {n.tag} {{ return true }}",
                "\t\t}",
                "\t}",
                "}",
                "return false",
            ])
        raise dsl.DSLError(f"ExtSubfieldPresent: unsupported path {n.path!r}")

    if isinstance(n, dsl.AIAHasMethodOtherThan):
        ext_expr = V.OID_BY_NAME[n.ext_oid].go_expr
        allowed_exprs = ", ".join(V.OID_BY_NAME[o].go_expr for o in n.allowed_oids)
        return _iife_bool([
            f"_e := util.GetExtFromCert(c, {ext_expr})",
            "if _e == nil { return false }",
            "var _ads []struct{ Method asn1.ObjectIdentifier; Location asn1.RawValue }",
            "if _, _err := asn1.Unmarshal(_e.Value, &_ads); _err != nil { return false }",
            f"_allowed := []asn1.ObjectIdentifier{{{allowed_exprs}}}",
            "for _, _ad := range _ads {",
            "\t_ok := false",
            "\tfor _, _a := range _allowed { if _ad.Method.Equal(_a) { _ok = true; break } }",
            "\tif !_ok { return true }",
            "}",
            "return false",
        ])

    if isinstance(n, dsl.AIAMethodLocationsTagInSet):
        ext_expr = V.OID_BY_NAME[n.ext_oid].go_expr
        method_expr = V.OID_BY_NAME[n.method_oid].go_expr
        tag_lits = ", ".join(str(t) for t in n.allowed_tags)
        return _iife_bool([
            f"_e := util.GetExtFromCert(c, {ext_expr})",
            "if _e == nil { return true }",
            "var _ads []struct{ Method asn1.ObjectIdentifier; Location asn1.RawValue }",
            "if _, _err := asn1.Unmarshal(_e.Value, &_ads); _err != nil { return false }",
            f"_target := {method_expr}",
            f"_tags := []int{{{tag_lits}}}",
            "for _, _ad := range _ads {",
            "\tif !_ad.Method.Equal(_target) { continue }",
            "\t_match := false",
            "\tfor _, _t := range _tags { if _ad.Location.Tag == _t { _match = true; break } }",
            "\tif !_match { return false }",
            "}",
            "return true",
        ])

    if isinstance(n, dsl.AIAMethodLocationsAnyMatchRegex):
        ext_expr = V.OID_BY_NAME[n.ext_oid].go_expr
        method_expr = V.OID_BY_NAME[n.method_oid].go_expr
        pat = _go_string(V.NAMED_REGEXES[n.pattern][0])
        return _iife_bool([
            f"_e := util.GetExtFromCert(c, {ext_expr})",
            "if _e == nil { return false }",
            "var _ads []struct{ Method asn1.ObjectIdentifier; Location asn1.RawValue }",
            "if _, _err := asn1.Unmarshal(_e.Value, &_ads); _err != nil { return false }",
            f"_target := {method_expr}",
            f"_re := regexp.MustCompile({pat})",
            "for _, _ad := range _ads {",
            "\tif !_ad.Method.Equal(_target) { continue }",
            "\tif _ad.Location.Tag != 6 { continue }",
            "\tif _re.Match(_ad.Location.Bytes) { return true }",
            "}",
            "return false",
        ])

    if isinstance(n, dsl.AIAAccessDescriptionCountInRange):
        oid = V.OID_BY_NAME["AiaOID"].go_expr
        hi = "math.MaxInt" if (n.hi == "MAX_INT" or (isinstance(n.hi, int) and n.hi > (1 << 62))) else str(n.hi)
        return _iife_bool([
            f"_e := util.GetExtFromCert(c, {oid})",
            "if _e == nil { return true }",
            "var _ads []struct{ Method asn1.ObjectIdentifier; Location asn1.RawValue }",
            "if _, _err := asn1.Unmarshal(_e.Value, &_ads); _err != nil { return false }",
            "_n := len(_ads)",
            f"return _n >= {n.lo} && _n <= {hi}",
        ])

    if isinstance(n, dsl.AIAAccessLocationUniquePerMethod):
        oid = V.OID_BY_NAME["AiaOID"].go_expr
        return _iife_bool([
            f"_e := util.GetExtFromCert(c, {oid})",
            "if _e == nil { return true }",
            "var _ads []struct{ Method asn1.ObjectIdentifier; Location asn1.RawValue }",
            "if _, _err := asn1.Unmarshal(_e.Value, &_ads); _err != nil { return false }",
            "_seen := map[string]bool{}",
            "for _, _ad := range _ads {",
            "\t_key := _ad.Method.String() + \"|\" + string(_ad.Location.FullBytes)",
            "\tif _seen[_key] { return false }",
            "\t_seen[_key] = true",
            "}",
            "return true",
        ])

    if isinstance(n, dsl.CRLDPHasNameRelative):
        return _iife_bool([
            "var _ev []byte",
            "for _, _ext := range c.Extensions {",
            "\tif len(_ext.Id) == 4 && _ext.Id[0] == 2 && _ext.Id[1] == 5 && _ext.Id[2] == 29 && _ext.Id[3] == 31 {",
            "\t\t_ev = _ext.Value; break",
            "\t}",
            "}",
            "if _ev == nil { return false }",
            "type _dpName struct {",
            "\tFullName     asn1.RawValue `asn1:\"optional,tag:0\"`",
            "\tRelativeName asn1.RawValue `asn1:\"optional,tag:1\"`",
            "}",
            "type _dp struct {",
            "\tDistributionPoint _dpName       `asn1:\"optional,tag:0\"`",
            "\tReasons           asn1.BitString `asn1:\"optional,tag:1\"`",
            "\tCRLIssuer         asn1.RawValue  `asn1:\"optional,tag:2\"`",
            "}",
            "var _dps []_dp",
            "if _, _err := asn1.Unmarshal(_ev, &_dps); _err != nil { return false }",
            "for _, _dp := range _dps {",
            "\tif _dp.DistributionPoint.RelativeName.FullBytes != nil { return true }",
            "}",
            "return false",
        ])

    if isinstance(n, dsl.CRLDPHasNameRelativeWithMultiIssuer):
        return _iife_bool([
            "var _ev []byte",
            "for _, _ext := range c.Extensions {",
            "\tif len(_ext.Id) == 4 && _ext.Id[0] == 2 && _ext.Id[1] == 5 && _ext.Id[2] == 29 && _ext.Id[3] == 31 {",
            "\t\t_ev = _ext.Value; break",
            "\t}",
            "}",
            "if _ev == nil { return false }",
            "type _dpName struct {",
            "\tFullName     asn1.RawValue `asn1:\"optional,tag:0\"`",
            "\tRelativeName asn1.RawValue `asn1:\"optional,tag:1\"`",
            "}",
            "type _dp struct {",
            "\tDistributionPoint _dpName       `asn1:\"optional,tag:0\"`",
            "\tReasons           asn1.BitString `asn1:\"optional,tag:1\"`",
            "\tCRLIssuer         asn1.RawValue  `asn1:\"optional,tag:2\"`",
            "}",
            "var _dps []_dp",
            "if _, _err := asn1.Unmarshal(_ev, &_dps); _err != nil { return false }",
            "for _, _dp := range _dps {",
            "\tif _dp.DistributionPoint.RelativeName.FullBytes == nil { continue }",
            "\t_b := _dp.CRLIssuer.Bytes",
            "\t_n := 0",
            "\tfor len(_b) > 0 {",
            "\t\tvar _v asn1.RawValue",
            "\t\t_rest, _err := asn1.Unmarshal(_b, &_v)",
            "\t\tif _err != nil { break }",
            "\t\t_n++",
            "\t\t_b = _rest",
            "\t}",
            "\tif _n > 1 { return true }",
            "}",
            "return false",
        ])

    if isinstance(n, dsl.ValidityDateAsn1TagInSet):
        tag_exprs = ", ".join(V.ASN1_BY_NAME[t].go_expr for t in n.allowed_tags)
        date_sel = "NotBefore" if n.date_field == "NotBefore" else "NotAfter"
        return _iife_bool([
            "type _tbsHead struct {",
            "\tVersion            int          `asn1:\"optional,explicit,tag:0,default:0\"`",
            "\tSerialNumber       asn1.RawValue",
            "\tSignatureAlgorithm asn1.RawValue",
            "\tIssuer             asn1.RawValue",
            "\tValidity           asn1.RawValue",
            "}",
            "var _t _tbsHead",
            "if _, _err := asn1.Unmarshal(c.RawTBSCertificate, &_t); _err != nil { return false }",
            "type _vy struct {",
            "\tNotBefore asn1.RawValue",
            "\tNotAfter  asn1.RawValue",
            "}",
            "var _v _vy",
            "if _, _err := asn1.Unmarshal(_t.Validity.FullBytes, &_v); _err != nil { return false }",
            f"_target := _v.{date_sel}",
            f"_allowed := []int{{{tag_exprs}}}",
            "if _target.Class != 0 { return false }",
            "for _, _a := range _allowed { if _target.Tag == _a { return true } }",
            "return false",
        ])

    if isinstance(n, dsl.CertPolicyExplicitTextHasEncodingTagInSet):
        tag_exprs = ", ".join(V.ASN1_BY_NAME[t].go_expr for t in n.allowed_tags)
        return _iife_bool([
            "var _ev []byte",
            "for _, _ext := range c.Extensions {",
            "\tif len(_ext.Id) == 4 && _ext.Id[0] == 2 && _ext.Id[1] == 5 && _ext.Id[2] == 29 && _ext.Id[3] == 32 {",
            "\t\t_ev = _ext.Value; break",
            "\t}",
            "}",
            "if _ev == nil { return false }",
            "type _pqi struct {",
            "\tPolicyQualifierId asn1.ObjectIdentifier",
            "\tQualifier         asn1.RawValue",
            "}",
            "type _pi struct {",
            "\tPolicyIdentifier asn1.ObjectIdentifier",
            "\tPolicyQualifiers []_pqi `asn1:\"optional\"`",
            "}",
            "var _pis []_pi",
            "if _, _err := asn1.Unmarshal(_ev, &_pis); _err != nil { return false }",
            f"_allowed := []int{{{tag_exprs}}}",
            "for _, _p := range _pis {",
            "\tfor _, _q := range _p.PolicyQualifiers {",
            "\t\t_qi := _q.PolicyQualifierId",
            # id-qt-unotice = 1.3.6.1.5.5.7.2.2 (9 arcs)
            "\t\tif !(len(_qi) == 9 && _qi[0] == 1 && _qi[1] == 3 && _qi[2] == 6 && _qi[3] == 1 && _qi[4] == 5 && _qi[5] == 5 && _qi[6] == 7 && _qi[7] == 2 && _qi[8] == 2) { continue }",
            "\t\t_b := _q.Qualifier.Bytes",
            "\t\tfor len(_b) > 0 {",
            "\t\t\tvar _v asn1.RawValue",
            "\t\t\t_rest, _err := asn1.Unmarshal(_b, &_v)",
            "\t\t\tif _err != nil { break }",
            "\t\t\t_b = _rest",
            "\t\t\tif _v.Class != 0 { continue }",
            "\t\t\tfor _, _a := range _allowed { if _v.Tag == _a { return true } }",
            "\t\t}",
            "\t}",
            "}",
            "return false",
        ])

    if isinstance(n, dsl.CertPolicyExplicitTextAllHaveEncodingTagInSet):
        tag_exprs = ", ".join(V.ASN1_BY_NAME[t].go_expr for t in n.allowed_tags)
        return _iife_bool([
            "var _ev []byte",
            "for _, _ext := range c.Extensions {",
            "\tif len(_ext.Id) == 4 && _ext.Id[0] == 2 && _ext.Id[1] == 5 && _ext.Id[2] == 29 && _ext.Id[3] == 32 {",
            "\t\t_ev = _ext.Value; break",
            "\t}",
            "}",
            "if _ev == nil { return true }",
            "type _pqi struct {",
            "\tPolicyQualifierId asn1.ObjectIdentifier",
            "\tQualifier         asn1.RawValue",
            "}",
            "type _pi struct {",
            "\tPolicyIdentifier asn1.ObjectIdentifier",
            "\tPolicyQualifiers []_pqi `asn1:\"optional\"`",
            "}",
            "var _pis []_pi",
            "if _, _err := asn1.Unmarshal(_ev, &_pis); _err != nil { return false }",
            f"_allowed := []int{{{tag_exprs}}}",
            "_displayTag := func(_tag int) bool { return _tag == 12 || _tag == 22 || _tag == 26 || _tag == 30 }",
            "_allowedTag := func(_tag int) bool {",
            "\tfor _, _a := range _allowed { if _tag == _a { return true } }",
            "\treturn false",
            "}",
            "for _, _p := range _pis {",
            "\tfor _, _q := range _p.PolicyQualifiers {",
            "\t\t_qi := _q.PolicyQualifierId",
            "\t\tif !(len(_qi) == 9 && _qi[0] == 1 && _qi[1] == 3 && _qi[2] == 6 && _qi[3] == 1 && _qi[4] == 5 && _qi[5] == 5 && _qi[6] == 7 && _qi[7] == 2 && _qi[8] == 2) { continue }",
            "\t\t_b := _q.Qualifier.Bytes",
            "\t\tfor len(_b) > 0 {",
            "\t\t\tvar _v asn1.RawValue",
            "\t\t\t_rest, _err := asn1.Unmarshal(_b, &_v)",
            "\t\t\tif _err != nil { return false }",
            "\t\t\t_b = _rest",
            "\t\t\tif _v.Class == 0 && _displayTag(_v.Tag) && !_allowedTag(_v.Tag) { return false }",
            "\t\t}",
            "\t}",
            "}",
            "return true",
        ])

    if isinstance(n, dsl.PolicyQualifierOIDInSet):
        import re as _re
        # Resolve OID constants → Go literals
        def _resolve_oid(oid_const: str) -> tuple[str, str]:
            if oid_const in V.OID_BY_NAME:
                oid_field = V.OID_BY_NAME[oid_const]
                oid_expr = oid_field.go_expr
                if oid_expr.startswith("asn1.ObjectIdentifier{"):
                    arcs = ",".join(_re.findall(r"\d+", oid_expr))
                    return f"asn1.ObjectIdentifier{{{arcs}}}", ""
                else:
                    dotted = ".".join(_re.findall(r"\d+", oid_expr))
                    return f'"{dotted}"', ""
            return f'"{oid_const}"', ""

        # Collect all allowed OID literals
        oid_consts = ()
        if n.oid_const:
            oid_consts = (n.oid_const,)
        elif n.oid_consts:
            oid_consts = n.oid_consts

        oid_lits = [_resolve_oid(oc) for oc in oid_consts]
        lit_list = "[]asn1.ObjectIdentifier{" + ",".join(l for l, _ in oid_lits) + "}"

        # Build comparison expression
        if len(oid_consts) == 1:
            oid_compare = f"_q.PolicyQualifierId.Equal({lit_list[1:-1]})"
        else:
            oid_compare = "_oid_in_list(_q.PolicyQualifierId, _allowed)"

        # Build function body
        if n.forbid_other:
            # "MUST only contain these OIDs" → check all qualifiers are in allowed set
            body_lines = [
                "var _ev []byte",
                "for _, _ext := range c.Extensions {",
                "\tif len(_ext.Id) == 4 && _ext.Id[0] == 2 && _ext.Id[1] == 5 && _ext.Id[2] == 29 && _ext.Id[3] == 32 {",
                "\t\t_ev = _ext.Value; break",
                "\t}",
                "}",
                "if _ev == nil { return false }",
                "type _pqi struct {",
                "\tPolicyQualifierId asn1.ObjectIdentifier",
                "\tQualifier         asn1.RawValue",
                "}",
                "type _pi struct {",
                "\tPolicyIdentifier asn1.ObjectIdentifier",
                "\tPolicyQualifiers []_pqi `asn1:\"optional\"`",
                "}",
                "var _pis []_pi",
                "if _, _err := asn1.Unmarshal(_ev, &_pis); _err != nil { return false }",
                "var _allowed = " + lit_list,
                "for _, _p := range _pis {",
                "\tfor _, _q := range _p.PolicyQualifiers {",
                "\t\tif !_oid_in_list(_q.PolicyQualifierId, _allowed) { return false }",
                "\t}",
                "}",
                "return true",
            ]
            # Add helper function if multiple OIDs
            if len(oid_consts) > 1:
                body_lines = ["func _oid_in_list(oid asn1.ObjectIdentifier, list []asn1.ObjectIdentifier) bool {",
                             "\tfor _, o := range list { if oid.Equal(o) { return true } }; return false }"] + body_lines
            return _iife_bool(body_lines)
        else:
            # Original semantics: at least one qualifier matches allowed OID
            body_lines = [
                "var _ev []byte",
                "for _, _ext := range c.Extensions {",
                "\tif len(_ext.Id) == 4 && _ext.Id[0] == 2 && _ext.Id[1] == 5 && _ext.Id[2] == 29 && _ext.Id[3] == 32 {",
                "\t\t_ev = _ext.Value; break",
                "\t}",
                "}",
                "if _ev == nil { return false }",
                "type _pqi struct {",
                "\tPolicyQualifierId asn1.ObjectIdentifier",
                "\tQualifier         asn1.RawValue",
                "}",
                "type _pi struct {",
                "\tPolicyIdentifier asn1.ObjectIdentifier",
                "\tPolicyQualifiers []_pqi `asn1:\"optional\"`",
                "}",
                "var _pis []_pi",
                "if _, _err := asn1.Unmarshal(_ev, &_pis); _err != nil { return false }",
            ]
            if len(oid_consts) > 1:
                body_lines += ["var _allowed = " + lit_list]
                body_lines += ["func _oid_in_list(oid asn1.ObjectIdentifier, list []asn1.ObjectIdentifier) bool {",
                              "\tfor _, o := range list { if oid.Equal(o) { return true } }; return false }"]
                body_lines += [
                    "for _, _p := range _pis {",
                    "\tfor _, _q := range _p.PolicyQualifiers {",
                    "\t\tif _oid_in_list(_q.PolicyQualifierId, _allowed) { return true }",
                    "\t}",
                    "}",
                    "return false",
                ]
            else:
                body_lines += [
                    "for _, _p := range _pis {",
                    "\tfor _, _q := range _p.PolicyQualifiers {",
                    f"\t\tif {oid_compare} {{ return true }}",
                    "\t}",
                    "}",
                    "return false",
                ]
            return _iife_bool(body_lines)

    if isinstance(n, dsl.PolicyQualifierOIDNotInSet):
        import re as _re
        oid_const = n.oid_const if hasattr(n, 'oid_const') else n.oid if hasattr(n, 'oid') else None
        if oid_const and oid_const in V.OID_BY_NAME:
            oid_field = V.OID_BY_NAME[oid_const]
            oid_expr = oid_field.go_expr
            if oid_expr.startswith("asn1.ObjectIdentifier{"):
                arcs = ",".join(_re.findall(r"\d+", oid_expr))
                oid_lit = f"asn1.ObjectIdentifier{{{arcs}}}"
                oid_compare = f"_q.PolicyQualifierId.Equal({oid_lit})"
            else:
                dotted = ".".join(_re.findall(r"\d+", oid_expr))
                oid_lit = f'"{dotted}"'
                oid_compare = f'_q.PolicyQualifierId.String() == {oid_lit}'
        else:
            oid_lit = f'"{oid_const}"'
            oid_compare = f'_q.PolicyQualifierId.String() == {oid_lit}'

        return _iife_bool([
            "var _ev []byte",
            "for _, _ext := range c.Extensions {",
            "\tif len(_ext.Id) == 4 && _ext.Id[0] == 2 && _ext.Id[1] == 5 && _ext.Id[2] == 29 && _ext.Id[3] == 32 {",
            "\t\t_ev = _ext.Value; break",
            "\t}",
            "}",
            "if _ev == nil { return true }",
            "type _pqi struct {",
            "\tPolicyQualifierId asn1.ObjectIdentifier",
            "\tQualifier         asn1.RawValue",
            "}",
            "type _pi struct {",
            "\tPolicyIdentifier asn1.ObjectIdentifier",
            "\tPolicyQualifiers []_pqi `asn1:\"optional\"`",
            "}",
            "var _pis []_pi",
            "if _, _err := asn1.Unmarshal(_ev, &_pis); _err != nil { return true }",
            "for _, _p := range _pis {",
            "\tfor _, _q := range _p.PolicyQualifiers {",
            f"\t\tif {oid_compare} {{ return false }}",
            "\t}",
            "}",
            "return true",
        ])

    if isinstance(n, dsl.AlgorithmIdentifierBytesMatch):
        # Matches: 'publicKeyAlgorithm MUST be id-ecPublicKey' etc.
        # Looks up OID constant and generates byte-level comparison
        import re as _re
        oid_const = n.oid_const
        oid_field = V.OID_BY_NAME.get(oid_const)
        if oid_field:
            oid_expr = oid_field.go_expr
            if oid_expr.startswith("asn1.ObjectIdentifier{"):
                arcs = ",".join(_re.findall(r"\d+", oid_expr))
                oid_lit = f"asn1.ObjectIdentifier{{{arcs}}}"
            else:
                dotted = ".".join(_re.findall(r"\d+", oid_expr))
                oid_lit = f'"{dotted}"'
        else:
            oid_lit = f'"{oid_const}"'

        if n.neg:
            # MUST NOT be these bytes
            return _iife_bool([
                "var _alg asn1.ObjectIdentifier",
                "switch t := any(c).(type) {",
                "\tcase interface{ GetSignatureAlgorithm() asn1.ObjectIdentifier }:",
                "\t\t_alg = t.GetSignatureAlgorithm()",
                "\tcase interface{ SignatureAlgorithm asn1.ObjectIdentifier }:",
                "\t\t_alg = t.SignatureAlgorithm",
                "\tdefault:",
                "\t\t// No algorithm field accessible; reject as non-match",
                "\t\treturn false",
                "}",
                f"\treturn !_alg.Equal({oid_lit})",
            ])
        else:
            # MUST be these bytes
            return _iife_bool([
                "var _alg asn1.ObjectIdentifier",
                "switch t := any(c).(type) {",
                "\tcase interface{ GetSignatureAlgorithm() asn1.ObjectIdentifier }:",
                "\t\t_alg = t.GetSignatureAlgorithm()",
                "\tcase interface{ SignatureAlgorithm asn1.ObjectIdentifier }:",
                "\t\t_alg = t.SignatureAlgorithm",
                "\tdefault:",
                "\t\t// No algorithm field accessible",
                "\t\treturn false",
                "}",
                f"\treturn _alg.Equal({oid_lit})",
            ])

    if isinstance(n, dsl.OidEq):
        f = V.lookup_anyfield(n.field)
        oid = V.OID_BY_NAME[n.oid].go_expr
        if oid.startswith("asn1.ObjectIdentifier{"):
            import re as _re
            dotted = ".".join(_re.findall(r"\d+", oid[oid.find("{"):]))
            return f'({f.go_expr}.String() == "{dotted}")'
        return f"{f.go_expr}.Equal({oid})"

    if isinstance(n, dsl.SubtreeIPListAnyHasOctetCount):
        f = V.lookup_anyfield(n.field)
        return _iife_bool([
            f"for _, _s := range {f.go_expr} {{",
            f"\tif len(_s.Data.IP)+len(_s.Data.Mask) == {n.count} {{ return true }}",
            f"}}",
            f"return false",
        ])

    if isinstance(n, dsl.SubtreeIPListVersionAllOctetCount):
        f = V.lookup_anyfield(n.field)
        ip_len = 4 if n.version == 4 else 16 if n.version == 6 else None
        if ip_len is None:
            raise dsl.DSLError(f"SubtreeIPListVersionAllOctetCount: unsupported version {n.version}")
        return _iife_bool([
            f"for _, _s := range {f.go_expr} {{",
            f"\tif len(_s.Data.IP) != {ip_len} {{ continue }}",
            f"\tif len(_s.Data.IP)+len(_s.Data.Mask) != {n.count} {{ return false }}",
            "}",
            "return true",
        ])

    if isinstance(n, dsl.BytesContainsOidDer):
        f = V.lookup_anyfield(n.field)
        oid_field = V.OID_BY_NAME[n.oid]
        oid_der_hex = _oid_to_der_hex(oid_field.go_expr)
        lit = _hex_literal(oid_der_hex)
        return f"bytes.Contains({f.go_expr}, {lit})"

    if isinstance(n, dsl.IPListAllOctetCountIn):
        f = V.lookup_anyfield(n.field)
        ok_clause = " || ".join(f"len(_ip) == {c}" for c in n.counts)
        return _iife_bool([
            f"for _, _ip := range {f.go_expr} {{",
            f"	if !({ok_clause}) {{ return false }}",
            f"}}",
            f"return true",
        ])
    if isinstance(n, dsl.SubtreeIPListAnyAllZero):
        f = V.lookup_anyfield(n.field)
        return _iife_bool([
            f"for _, _s := range {f.go_expr} {{",
            f"	if len(_s.Data.IP)+len(_s.Data.Mask) != {n.count} {{ continue }}",
            f"	_allz := true",
            f"	for _, _b := range _s.Data.IP {{ if _b != 0 {{ _allz = false; break }} }}",
            f"	if _allz {{",
            f"		for _, _b := range _s.Data.Mask {{ if _b != 0 {{ _allz = false; break }} }}",
            f"	}}",
            f"	if _allz {{ return true }}",
            f"}}",
            f"return false",
        ])

    if isinstance(n, dsl.SubtreeIPListAnyHasOctetCountAndNotAllZero):
        f = V.lookup_anyfield(n.field)
        return _iife_bool([
            f"for _, _s := range {f.go_expr} {{",
            f"	if len(_s.Data.IP)+len(_s.Data.Mask) != {n.count} {{ continue }}",
            f"	_anyNz := false",
            f"	for _, _b := range _s.Data.IP {{ if _b != 0 {{ _anyNz = true; break }} }}",
            f"	if !_anyNz {{",
            f"		for _, _b := range _s.Data.Mask {{ if _b != 0 {{ _anyNz = true; break }} }}",
            f"	}}",
            f"	if _anyNz {{ return true }}",
            f"}}",
            f"return false",
        ])

    if isinstance(n, dsl.SubtreeStringListAllMatch):
        f = V.lookup_anyfield(n.field)
        item_var = "_item"
        inner = _emit(n.predicate, in_item=True, item_var=item_var)
        return _iife_bool([
            f"for _, _s := range {f.go_expr} {{",
            f"	{item_var} := _s.Data",
            f"	if !({inner}) {{ return false }}",
            f"}}",
            f"return len({f.go_expr}) > 0",
        ])
    if isinstance(n, dsl.SubtreeStringListAnyMatch):
        f = V.lookup_anyfield(n.field)
        item_var = "_item"
        inner = _emit(n.predicate, in_item=True, item_var=item_var)
        return _iife_bool([
            f"for _, _s := range {f.go_expr} {{",
            f"	{item_var} := _s.Data",
            f"	if ({inner}) {{ return true }}",
            f"}}",
            f"return false",
        ])
    if isinstance(n, dsl.SubtreeStringListHasNonEmptyOrEmptyMarker):
        f = V.lookup_anyfield(n.field)
        return _iife_bool([
            "_hasNonEmpty := false",
            "_hasEmptyMarker := false",
            f"for _, _s := range {f.go_expr} {{",
            "\tif _s.Data == \"\" { _hasEmptyMarker = true } else { _hasNonEmpty = true }",
            "}",
            "return _hasNonEmpty || _hasEmptyMarker",
        ])
    if isinstance(n, dsl.SubtreeStringListHasEmptyMarker):
        f = V.lookup_anyfield(n.field)
        return _iife_bool([
            f"for _, _s := range {f.go_expr} {{",
            "\tif _s.Data == \"\" { return true }",
            "}",
            "return false",
        ])
    if isinstance(n, dsl.NameConstraintsExcludedSubtreesEmpty):
        return _iife_bool([
            "_ext := util.GetExtFromCert(c, util.NameConstOID)",
            "if _ext == nil { return true }",
            "var _seq asn1.RawValue",
            "if _, _err := asn1.Unmarshal(_ext.Value, &_seq); _err != nil { return false }",
            "_b := _seq.Bytes",
            "for len(_b) > 0 {",
            "\tvar _v asn1.RawValue",
            "\t_rest, _err := asn1.Unmarshal(_b, &_v)",
            "\tif _err != nil { return false }",
            "\tif _v.Class == 2 && _v.Tag == 1 { return len(_v.Bytes) == 0 }",
            "\t_b = _rest",
            "}",
            "return true",
        ])
    if isinstance(n, dsl.NameConstraintsPermittedSubtreesNonEmpty):
        return _iife_bool([
            "_ext := util.GetExtFromCert(c, util.NameConstOID)",
            "if _ext == nil { return false }",
            "var _seq asn1.RawValue",
            "if _, _err := asn1.Unmarshal(_ext.Value, &_seq); _err != nil { return false }",
            "_b := _seq.Bytes",
            "for len(_b) > 0 {",
            "\tvar _v asn1.RawValue",
            "\t_rest, _err := asn1.Unmarshal(_b, &_v)",
            "\tif _err != nil { return false }",
            "\tif _v.Class == 2 && _v.Tag == 0 { return len(_v.Bytes) > 0 }",
            "\t_b = _rest",
            "}",
            "return false",
        ])
    if isinstance(n, dsl.SubtreeStringListAllMatchOrEmpty):
        f = V.lookup_anyfield(n.field)
        item_var = "_item"
        inner = _emit(n.predicate, in_item=True, item_var=item_var)
        return _iife_bool([
            f"if len({f.go_expr}) == 0 {{ return true }}",
            f"for _, _s := range {f.go_expr} {{",
            f"	{item_var} := _s.Data",
            f"	if !({inner}) {{ return false }}",
            f"}}",
            f"return true",
        ])
    if isinstance(n, dsl.SubtreeIPListAllOctetCountIn):
        f = V.lookup_anyfield(n.field)
        ok = " || ".join(f"_n == {c}" for c in n.counts)
        return _iife_bool([
            f"for _, _s := range {f.go_expr} {{",
            f"\t_n := len(_s.Data.IP) + len(_s.Data.Mask)",
            f"\tif !({ok}) {{ return false }}",
            f"}}",
            f"return true",
        ])
    if isinstance(n, dsl.SubtreeIPMaskValidCIDR):
        f = V.lookup_anyfield(n.field)
        # Valid CIDR mask = contiguous high-order 1-bits then zeros.
        # Walk bits MSB-first across all mask bytes; once a 0 is seen,
        # any subsequent 1 invalidates the entry.
        return _iife_bool([
            f"for _, _s := range {f.go_expr} {{",
            f"\t_seenZero := false",
            f"\tfor _, _b := range _s.Data.Mask {{",
            f"\t\tfor _bit := 7; _bit >= 0; _bit-- {{",
            f"\t\t\tif (_b >> uint(_bit)) & 1 == 1 {{",
            f"\t\t\t\tif _seenZero {{ return false }}",
            f"\t\t\t}} else {{",
            f"\t\t\t\t_seenZero = true",
            f"\t\t\t}}",
            f"\t\t}}",
            f"\t}}",
            f"}}",
            f"return true",
        ])
    if isinstance(n, dsl.SubtreeIPVersionMaskValidCIDR):
        f = V.lookup_anyfield(n.field)
        ip_len = 4 if n.version == 4 else 16 if n.version == 6 else None
        if ip_len is None:
            raise dsl.DSLError(f"SubtreeIPVersionMaskValidCIDR: unsupported version {n.version}")
        return _iife_bool([
            f"for _, _s := range {f.go_expr} {{",
            f"\tif len(_s.Data.IP) != {ip_len} {{ continue }}",
            "\t_seenZero := false",
            "\tfor _, _b := range _s.Data.Mask {",
            "\t\tfor _bit := 7; _bit >= 0; _bit-- {",
            "\t\t\tif (_b >> uint(_bit)) & 1 == 1 {",
            "\t\t\t\tif _seenZero { return false }",
            "\t\t\t} else {",
            "\t\t\t\t_seenZero = true",
            "\t\t\t}",
            "\t\t}",
            "\t}",
            "}",
            "return true",
        ])



    # ----- new atoms -----
    if isinstance(n, dsl.FieldContains):
        f = V.lookup_anyfield(n.field)
        lit = _go_string(n.substring)
        if f.semantic == "string":
            return f"strings.Contains({f.go_expr}, {lit})"
        return _iife_bool([
            f"for _, _x := range {f.go_expr} {{",
            f"\tif !strings.Contains(_x, {lit}) {{ return false }}",
            "\t}}",
            f"return len({f.go_expr}) > 0",
        ])

    if isinstance(n, dsl.FieldNotMatchesRegex):
        f = V.lookup_anyfield(n.field)
        if n.pattern not in V.NAMED_REGEXES:
            raise dsl.DSLError(f"FieldNotMatchesRegex: unknown named regex \'{n.pattern}\'")
        pat = _go_string(V.NAMED_REGEXES[n.pattern][0])
        if f.semantic == "string":
            return f"!regexp.MustCompile({pat}).MatchString({f.go_expr})"
        return _iife_bool([
            f"_re := regexp.MustCompile({pat})",
            f"for _, _x := range {f.go_expr} {{",
            f"\tif _re.MatchString(_x) {{ return false }}",
            "\t}}",
            f"return len({f.go_expr}) > 0",
        ])

    if isinstance(n, dsl.CrossFieldEq):
        fa = V.lookup_anyfield(n.field_a)
        fb = V.lookup_anyfield(n.field_b)
        if fa.semantic == "bytes" and fb.semantic == "bytes":
            # []byte slices aren't `==`-comparable in Go; DER byte equality.
            return f"bytes.Equal({fa.go_expr}, {fb.go_expr})"
        if fa.semantic in ("string", "int") and fb.semantic in ("string", "int"):
            return f"({fa.go_expr} == {fb.go_expr})"
        raise dsl.DSLError(
            f"CrossFieldEq: non-comparable semantics "
            f"{fa.semantic}/{fb.semantic} for '{n.field_a}'/'{n.field_b}'")

    # ----- merged atoms from app/dsl -----
    if isinstance(n, dsl.SerialNumberInRange):
        return _iife_bool([
            f"_snLen := len(c.SerialNumber)",
            f"if _snLen < {n.lo} {{ return false }}",
            f"return _snLen <= {n.hi}",
        ])

    if isinstance(n, dsl.CRLNumberInRange):
        # CRLNumber: requires CRL-specific zcrypto access (c.CRLNumber)
        _lo = n.lo
        _hi = n.hi if n.hi != "MAX_INT" else "math.MaxInt"
        return _iife_bool([
            f"// CRLNumber in range [{_lo}, {_hi}]",
            f"// Requires CRL-specific zcrypto access (c.CRLNumber)",
            f"_crlNum := c.CRLNumber",
            f"return _crlNum >= {_lo} && _crlNum <= {_hi}",
        ])

    if isinstance(n, dsl.PathLenConstraintHas):
        # pathLenConstraint comparison: eq/le/lt/ge/gt vs integer value
        ops = {"eq": "==", "le": "<=", "lt": "<", "ge": ">=", "gt": ">"}
        if n.op not in ops:
            raise dsl.DSLError(f"PathLenConstraintHas: unknown op {n.op!r}")
        if n.value is None:
            # None means constraint: pathLen must NOT be present
            return "(c.MaxPathLen < 0 && !c.MaxPathLenZero)"
        return f"(c.MaxPathLen {ops[n.op]} {n.value})"

    if isinstance(n, dsl.TimeZoneUTC):
        # Check validity times are UTC-encoded (Z suffix, no fractional)
        return _iife_bool([
            "// UTCTime encoding check: no fractional seconds, Z suffix",
            f"if c.NotBefore.Location() != time.UTC {{ return false }}",
            f"if c.NotAfter.Location() != time.UTC {{ return false }}",
            "// Check for absence of fractional seconds",
            f"return c.NotBefore.Unix() == c.NotBefore.Unix() && "
            f"c.NotAfter.Unix() == c.NotAfter.Unix()",
        ])

    if isinstance(n, dsl.URISchemeNotInSet):
        # Check no URI in field uses forbidden schemes
        _field = V.lookup_anyfield(n.list_field)
        _schemes = "[]string{" + ",".join(_go_string(s) for s in n.excluded_schemes) + "}"
        return _iife_bool([
            f"// URISchemeNotInSet: excluded={n.excluded_schemes}",
            f"_schemes := {_schemes}",
            f"for _, _uri := range {_field.go_expr} {{",
            f"\tfor _, _sch := range _schemes {{",
            f"\t\tif strings.HasPrefix(_uri, _sch+\":\") {{ return false }}",
            "\t}",
            "\t}",
            "return true",
        ])

    if isinstance(n, dsl.ExtensionURISchemeInSet):
        # Check all URIs in extension use only allowed schemes
        _ext_oid = V.lookup_oid(n.oid)
        _schemes = "[]string{" + ",".join(_go_string(s) for s in n.allowed_schemes) + "}"
        return _iife_bool([
            f"// ExtensionURISchemeInSet: {n.oid} allowed={n.allowed_schemes}",
            f"// Requires extension-specific URI extraction from raw DER",
            f"return true",
        ])

    if isinstance(n, dsl.CrossFieldMatch):
        # field_a must match field_b via the specified operator
        fa = V.lookup_anyfield(n.field_a)
        fb = V.lookup_anyfield(n.field_b)
        if n.op == "eq":
            if fa.semantic == "bytes" and fb.semantic == "bytes":
                return f"bytes.Equal({fa.go_expr}, {fb.go_expr})"
            return f"({fa.go_expr} == {fb.go_expr})"
        raise dsl.DSLError(f"CrossFieldMatch: unknown op {n.op!r}")

    if isinstance(n, dsl.PolicyHasQualifierOID):
        # CertPolicy extension must have qualifier with given OID
        _oid = V.lookup_oid(n.oid_const)
        return _iife_bool([
            f"// PolicyHasQualifierOID: {n.oid_const}",
            f"// Requires raw DER parsing of CertPolicy extension",
            f"return false",
        ])

    if isinstance(n, dsl.PolicyQualifierCountInRange):
        # Count of policyQualifiers in any PolicyInformation must be in range
        _lo = n.lo
        _hi = n.hi if n.hi != "MAX_INT" else "math.MaxInt"
        return _iife_bool([
            f"// PolicyQualifierCountInRange: [{_lo}, {_hi}]",
            f"// Requires raw DER parsing of CertPolicy extension",
            f"return false",
        ])

    if isinstance(n, dsl.PolicyQualifierEncodedAsTag):
        # policyQualifier qualifier field must be one of given ASN.1 types
        _types = n.types
        return _iife_bool([
            f"// PolicyQualifierEncodedAsTag: {n.types}",
            f"// Requires raw DER tag inspection of qualifier field",
            f"return false",
        ])

    if isinstance(n, dsl.RDNHasSingleAttributeType):
        # Each RDN must have exactly one AVA (no multi-AV RDN)
        return _iife_bool([
            "// RDNHasSingleAttributeType: each RDN must have exactly one AVA",
            "for _, rdn := range c.Subject.Numbers {",
            "\tif len(rdn.Numbers) != 1 { return false }",
            "}",
            "return true",
        ])

    if isinstance(n, dsl.DNNoDuplicateAttributeTypes):
        # No AttributeType appears in more than one RDN
        return _iife_bool([
            "// DNNoDuplicateAttributeTypes: no duplicate attribute types",
            "for i, rdn := range c.Subject.Numbers {",
            "\tfor _, attr := range rdn.Numbers {",
            "\t\tfor j, rdn2 := range c.Subject.Numbers {",
            "\t\t\tif i == j { continue }",
            "\t\t\tfor _, attr2 := range rdn2.Numbers {",
            "\t\t\t\tif attr.Type.String() == attr2.Type.String() { return false }",
            "\t\t\t}",
            "\t\t}",
            "\t}",
            "}",
            "return true",
        ])

    if isinstance(n, dsl.DNComponentOrderMatches):
        # DN components must match specified order
        return _iife_bool([
            f"// DNComponentOrderMatches: order_type={n.order_type!r}",
            f"// Requires profile-specific order rules",
            f"return true",
        ])

    if isinstance(n, dsl.ExtAccessLocationMatchesType):
        # Each AccessDescription accessLocation must match specified tag type
        _tag_names = {0: "otherName", 1: "rfc822Name", 2: "dNSName",
                      3: "x400Address", 4: "directoryName", 5: "ediPartyName",
                      6: "uniformResourceIdentifier", 7: "iPAddress", 8: "registeredID"}
        _tag_name = _tag_names.get(n.tag, f"tag{n.tag}")
        return _iife_bool([
            f"// ExtAccessLocationMatchesType: tag={n.tag} ({_tag_name})",
            f"// Requires extension-specific AccessDescription inspection",
            f"return false",
        ])

    if isinstance(n, dsl.ExtAccessDescriptionOrdered):
        # AccessDescription entries must be sorted by accessMethod OID
        return _iife_bool([
            "// ExtAccessDescriptionOrdered: sorted by accessMethod OID",
            "// Requires extension-specific OID comparison",
            "return true",
        ])

    if isinstance(n, dsl.OIDBytesMatchHex):
        # OID constant DER bytes must match hex string
        return _iife_bool([
            f"// OIDBytesMatchHex: {n.oid_const} == {n.hex_bytes[:40]}...",
            f"// Extract OID DER bytes, compare with hex literal",
            f"return false",
        ])

    if isinstance(n, dsl.FieldMatchesNoForbiddenChars):
        # String field must not contain any forbidden characters
        f = V.lookup_anyfield(n.field)
        if f.semantic != "string":
            raise dsl.DSLError(
                f"FieldMatchesNoForbiddenChars: field {n.field} semantic {f.semantic} not supported")
        return _iife_bool([
            f"for _, _c := range {f.go_expr} {{",
            f"\tswitch _c {{",
            *[f"\tcase {chr(34)+c+chr(34)}: return false" for c in n.forbidden_chars],
            "\t}",
            "\t}",
            f"return true",
        ])

    if isinstance(n, dsl.SubtreeIPListAnyHasOctetCountIn):
        # Any subtree in NameConstraints IP list has octet count in range
        return _iife_bool([
            f"// SubtreeIPListAnyHasOctetCountIn: counts={n.counts}",
            f"// Requires NameConstraints raw DER parsing",
            f"return false",
        ])

    if isinstance(n, dsl.CertPolicyExplicitTextHasEncodingTagNotInSet):
        # explicitText must NOT be encoded as forbidden tag types
        return _iife_bool([
            f"// CertPolicyExplicitTextHasEncodingTagNotInSet: forbidden={n.forbidden_tags}",
            f"// Requires CertPolicy raw DER parsing of explicitText",
            f"return false",
        ])

    if isinstance(n, dsl.WildcardFilter):
        f = V.lookup_anyfield(n.list_field)
        prefix_lit = _go_string(n.prefix)
        item_var = "_item"
        inner = _emit(n.predicate, in_item=True, item_var=item_var)
        return _iife_bool([
            f"for _, {item_var} := range {f.go_expr} {{",
            f"\tif strings.HasPrefix({item_var}, {prefix_lit}) {{",
            f"\t\tif !({inner}) {{ return false }}",
            "	}",
            "\t}",
            f"return true",
        ])

    if isinstance(n, dsl.DNSNamesFQDNOrWildcardPortionMatchesRegex):
        if n.pattern not in V.NAMED_REGEXES:
            raise dsl.DSLError(f"DNSNamesFQDNOrWildcardPortionMatchesRegex: unknown named regex '{n.pattern}'")
        pat = _go_string(V.NAMED_REGEXES[n.pattern][0])
        return _iife_bool([
            f"_re := regexp.MustCompile({pat})",
            "for _, _name := range c.DNSNames {",
            "\t_target := _name",
            "\tif strings.HasPrefix(_target, \"*.\") { _target = _target[2:] }",
            "\tif !_re.MatchString(_target) { return false }",
            "}",
            "return true",
        ])

    if isinstance(n, dsl.DNSOnionNamesHaveValidTorV3Address):
        return _iife_bool([
            "for _, _name := range c.DNSNames {",
            "\t_labels := strings.Split(strings.ToLower(_name), \".\")",
            "\tif len(_labels) == 0 || _labels[len(_labels)-1] != \"onion\" { continue }",
            "\tif len(_labels) < 2 { return false }",
            "\t_onion := _labels[len(_labels)-2]",
            "\tif len(_onion) != 56 { return false }",
            "\tfor _, _r := range _onion {",
            "\t\tif !((_r >= 'a' && _r <= 'z') || (_r >= '2' && _r <= '7')) { return false }",
            "\t}",
            "}",
            "return true",
        ])

    if isinstance(n, dsl.DomainNamesDoNotEndWithIPReverseZoneSuffix):
        return _iife_bool([
            "_bad := func(_name string) bool {",
            "\t_s := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(_name)), \".\")",
            "\treturn _s == \"in-addr.arpa\" || strings.HasSuffix(_s, \".in-addr.arpa\") || _s == \"ip6.arpa\" || strings.HasSuffix(_s, \".ip6.arpa\")",
            "}",
            "for _, _name := range c.DNSNames {",
            "\tif _bad(_name) { return false }",
            "}",
            "if c.Subject.CommonName != \"\" && _bad(c.Subject.CommonName) { return false }",
            "return true",
        ])

    if isinstance(n, dsl.ScalarInList):
        fa = V.lookup_anyfield(n.scalar_field)
        fl = V.lookup_anyfield(n.list_field)
        # If scalar is empty, condition is vacuously satisfied (CN if not present)
        # if non-empty, must appear as element of list.
        return _iife_bool([
            f"if {fa.go_expr} == \"\" {{ return true }}",
            f"for _, _x := range {fl.go_expr} {{",
            f"    if _x == {fa.go_expr} {{ return true }}",
            "}",
            f"return false",
        ])

    if isinstance(n, dsl.ScalarInAnyOfLists):
        fa = V.lookup_anyfield(n.scalar_field)
        body = [f"if {fa.go_expr} == \"\" {{ return true }}"]
        for lname in n.list_fields:
            fl = V.lookup_anyfield(lname)
            body.append(f"for _, _x := range {fl.go_expr} {{")
            if fl.semantic == "ip_list":
                # net.IP comparison: stringify and compare
                body.append(f"    if _x.String() == {fa.go_expr} {{ return true }}")
            else:
                body.append(f"    if _x == {fa.go_expr} {{ return true }}")
            body.append("}")
        body.append("return false")
        return _iife_bool(body)

    if isinstance(n, dsl.ListSubsetOfList):
        fs = V.lookup_anyfield(n.source_list)
        ft = V.lookup_anyfield(n.target_list)
        return _iife_bool([
            f"for _, _src := range {fs.go_expr} {{",
            "\t_found := false",
            f"\tfor _, _dst := range {ft.go_expr} {{",
            "\t\tif _dst == _src { _found = true; break }",
            "\t}",
            "\tif !_found { return false }",
            "}",
            "return true",
        ])

    if isinstance(n, dsl.IPv4Conditional):
        f = V.lookup_anyfield(n.field)
        ip4 = _emit(n.ipv4_predicate, in_item=True, item_var="_ip")
        ip6 = _emit(n.ipv6_predicate, in_item=True, item_var="_ip")
        return _iife_bool([
            f"for _, _ip := range {f.go_expr} {{",
            f"	if len(_ip) == 4 {{",
            f"		if !({ip4}) {{ return false }}",
            "	} else if len(_ip) == 16 {",
            f"		if !({ip6}) {{ return false }}",
            "	}",
            "}",
            f"return true",
        ])

    if isinstance(n, dsl.SubtreeIPv4Conditional):
        f = V.lookup_anyfield(n.field)
        ip4 = _emit(n.ipv4_predicate, in_item=True, item_var="_ip")
        ip6 = _emit(n.ipv6_predicate, in_item=True, item_var="_ip")
        return _iife_bool([
            f"for _, _s := range {f.go_expr} {{",
            f"\t_n := len(_s.Data.IP) + len(_s.Data.Mask)",
            f"\t_ip := make([]byte, _n)",
            f"\t_ = _ip",
            f"\tif len(_s.Data.IP) == 4 {{",
            f"\t\tif !({ip4}) {{ return false }}",
            f"\t}} else if len(_s.Data.IP) == 16 {{",
            f"\t\tif !({ip6}) {{ return false }}",
            f"\t}}",
            f"}}",
            f"return true",
        ])


    if isinstance(n, dsl.ExtHasGeneralNameWithTag):
        oid = V.OID_BY_NAME[n.oid].go_expr
        return _iife_bool([
            f"_ext := util.GetExtFromCert(c, {oid})",
            f"if _ext == nil {{ return false }}",
            f"res, err := util.AllAlternateNameWithTagAreIA5(_ext, {n.tag})",
            f"if err != nil {{ return false }}",
            f"return res",
        ])

    if isinstance(n, dsl.ExtHasAnyGeneralNameOfTag):
        oid = V.OID_BY_NAME[n.oid].go_expr
        # Re-parse the extension as SEQUENCE OF GeneralName and look for any
        # element whose context-class CHOICE tag matches n.tag. zcrypto's
        # parsed Certificate exposes only a few CHOICE alternatives (DNSNames,
        # EmailAddresses, URIs, IPAddresses), so this walk is required to
        # detect directoryName / otherName / etc.
        return _iife_bool([
            f"_ext := util.GetExtFromCert(c, {oid})",
            "if _ext == nil { return false }",
            "var _seq asn1.RawValue",
            "if _, err := asn1.Unmarshal(_ext.Value, &_seq); err != nil { return false }",
            "_rest := _seq.Bytes",
            "for len(_rest) > 0 {",
            "\tvar _v asn1.RawValue",
            "\tnext, err := asn1.Unmarshal(_rest, &_v)",
            "\tif err != nil { return false }",
            "\t_rest = next",
            f"\tif _v.Class == 2 && _v.Tag == {n.tag} {{ return true }}",
            "}",
            "return false",
        ])

    if isinstance(n, dsl.DomainComponentOrdered):
        # Walk c.Subject.OriginalRDNS (raw RDN sequence) checking domainComponent
        # ordering. domainComponent OID = 0.9.2342.19200300.100.1.25 (RFC 4519).
        # Valid ordering: all DC RDNs must form a single contiguous block.
        # OriginalRDNS is []RelativeDistinguishedNameSET; each set is
        # []AttributeTypeAndValue, so we iterate over both layers.
        return _iife_bool([
            "_prev := -1",
            "for i, rdn := range c.Subject.OriginalRDNS {",
            "    _isDC := false",
            "    for _, atv := range rdn {",
            '        if atv.Type.String() == "0.9.2342.19200300.100.1.25" {',
            "            _isDC = true",
            "            break",
            "        }",
            "    }",
            "    if _isDC {",
            "        if _prev == -1 {",
            "            _prev = i",
            "        } else if i != _prev+1 {",
            "            return false",
            "        }",
            "    } else if _prev != -1 {",
            "        return false",
            "    }",
            "}",
            "return true",
        ])

    # ---- New extension-aware atoms ----
    if isinstance(n, dsl.CertificatePoliciesHasNoPolicyQualifiers):
        oid = V.OID_BY_NAME["CertPolicyOID"].go_expr
        return _iife_bool([
            "_ext := util.GetExtFromCert(c, " + oid + ")",
            "if _ext == nil { return true }",
            "type _pqi struct {",
            "\tPolicyQualifierId asn1.ObjectIdentifier",
            "\tQualifier         asn1.RawValue",
            "}",
            "type _pi struct {",
            "\tPolicyIdentifier asn1.ObjectIdentifier",
            "\tPolicyQualifiers []_pqi `asn1:\"optional\"`",
            "}",
            "var _pis []_pi",
            "if _, err := asn1.Unmarshal(_ext.Value, &_pis); err != nil { return false }",
            "for _, pi := range _pis {",
            "\tif len(pi.PolicyQualifiers) > 0 { return false }",
            "}",
            "return true",
        ])

    if isinstance(n, dsl.ExtPolicyQualifierOIDInSet):
        # Check Certificate Policies extension: ALL qualifiers must be in the allowed set.
        # "MUST contain only permitted policyQualifiers" → any non-allowed qualifier → fail.
        oid = V.OID_BY_NAME["CertPolicyOID"].go_expr
        # Build the allowed OID check expression
        allowed_checks = []
        for oid_const in n.allowed_oid_consts:
            oid_info = V.OID_BY_NAME.get(oid_const)
            if oid_info is None:
                raise dsl.DSLError(f"ExtPolicyQualifierOIDInSet: unknown OID {oid_const}")
            allowed_checks.append(f'pq.PolicyQualifierId.Equal({oid_info.go_expr})')
        allowed_expr = " || ".join(allowed_checks)
        return _iife_bool([
            "_ext := util.GetExtFromCert(c, " + oid + ")",
            "if _ext == nil { return true }",
            "type _pqi struct {",
            "\tPolicyQualifierId asn1.ObjectIdentifier",
            "\tQualifier         asn1.RawValue",
            "}",
            "type _pi struct {",
            "\tPolicyIdentifier asn1.ObjectIdentifier",
            "\tPolicyQualifiers []_pqi `asn1:\"optional\"`",
            "}",
            "var _pis []_pi",
            "if _, err := asn1.Unmarshal(_ext.Value, &_pis); err != nil { return false }",
            "for _, pi := range _pis {",
            "\tfor _, pq := range pi.PolicyQualifiers {",
            f"\t\tif !({allowed_expr}) {{ return false }}",
            "\t}",
            "}",
            "return true",
        ])

    if isinstance(n, dsl.ExtPolicyQualifierOIDNotInSet):
        # Check Certificate Policies extension does NOT contain forbidden qualifier OID
        oid = V.OID_BY_NAME["CertPolicyOID"].go_expr
        _forbidden_oid = V.OID_BY_NAME.get(n.forbidden_oid_const)
        if _forbidden_oid is None:
            raise dsl.DSLError(f"ExtPolicyQualifierOIDNotInSet: unknown OID {n.forbidden_oid_const}")
        forbidden_go = _forbidden_oid.go_expr
        return _iife_bool([
            "_ext := util.GetExtFromCert(c, " + oid + ")",
            "if _ext == nil { return true }",
            "type _pqi struct {",
            "\tPolicyQualifierId asn1.ObjectIdentifier",
            "\tQualifier         asn1.RawValue",
            "}",
            "type _pi struct {",
            "\tPolicyIdentifier asn1.ObjectIdentifier",
            "\tPolicyQualifiers []_pqi `asn1:\"optional\"`",
            "}",
            "var _pis []_pi",
            "if _, err := asn1.Unmarshal(_ext.Value, &_pis); err != nil { return false }",
            "for _, pi := range _pis {",
            "\tfor _, pq := range pi.PolicyQualifiers {",
            f"\t\tif pq.PolicyQualifierId.Equal({forbidden_go}) {{ return false }}",
            "\t}",
            "}",
            "return true",
        ])

    if isinstance(n, dsl.ExtKeyUsageHasBit):
        # Check ExtKeyUsage extension has the specified OID present.
        # Supports both stdlib x509.ExtKeyUsage* constants (e.g., ServerAuth)
        # and OID-based EKU (e.g., TechnicallyConstrainedCA, Any) via util.HasEKU
        # with inline OID literal.
        _std_bits = {
            "DigitalSignature": "x509.ExtKeyUsageDigitalSignature",
            "NonRepudiation": "x509.ExtKeyUsageNonRepudiation",
            "KeyEncipherment": "x509.ExtKeyUsageKeyEncipherment",
            "DataEncipherment": "x509.ExtKeyUsageDataEncipherment",
            "KeyAgreement": "x509.ExtKeyUsageKeyAgreement",
            "KeyCertSign": "x509.ExtKeyUsageKeyCertSign",
            "CRLSign": "x509.ExtKeyUsageCRLSign",
            "EncipherOnly": "x509.ExtKeyUsageEncipherOnly",
            "DecipherOnly": "x509.ExtKeyUsageDecipherOnly",
        }
        if n.bit in _std_bits:
            return f"util.HasEKU(c, {_std_bits[n.bit]})"
        # OID-based EKU: look up in vocab (e.g., TechnicallyConstrainedCA → util.TechnicallyConstrainedCAEKU)
        ek = V.EKU_BY_NAME.get(n.bit)
        if ek is None:
            raise dsl.DSLError(f"ExtKeyUsageHasBit: unknown EKU bit {n.bit!r}")
        return f"util.HasEKU(c, {ek.go_expr})"

    if isinstance(n, dsl.ExtKeyUsageNotHasBit):
        # Check ExtKeyUsage extension does NOT have the specified OID.
        _std_bits = {
            "DigitalSignature": "x509.ExtKeyUsageDigitalSignature",
            "NonRepudiation": "x509.ExtKeyUsageNonRepudiation",
            "KeyEncipherment": "x509.ExtKeyUsageKeyEncipherment",
            "DataEncipherment": "x509.ExtKeyUsageDataEncipherment",
            "KeyAgreement": "x509.ExtKeyUsageKeyAgreement",
            "KeyCertSign": "x509.ExtKeyUsageKeyCertSign",
            "CRLSign": "x509.ExtKeyUsageCRLSign",
            "EncipherOnly": "x509.ExtKeyUsageEncipherOnly",
            "DecipherOnly": "x509.ExtKeyUsageDecipherOnly",
        }
        if n.bit in _std_bits:
            return f"!util.HasEKU(c, {_std_bits[n.bit]})"
        ek = V.EKU_BY_NAME.get(n.bit)
        if ek is None:
            raise dsl.DSLError(f"ExtKeyUsageNotHasBit: unknown EKU bit {n.bit!r}")
        return f"!util.HasEKU(c, {ek.go_expr})"

    if isinstance(n, dsl.ExtKeyUsageAllBitsInSet):
        # Check ExtKeyUsage extension has EXACTLY the specified EKU set (no more, no less)
        # Supports both stdlib and OID-based EKU values.
        _std_bits = {
            "DigitalSignature": "x509.ExtKeyUsageDigitalSignature",
            "NonRepudiation": "x509.ExtKeyUsageNonRepudiation",
            "KeyEncipherment": "x509.ExtKeyUsageKeyEncipherment",
            "DataEncipherment": "x509.ExtKeyUsageDataEncipherment",
            "KeyAgreement": "x509.ExtKeyUsageKeyAgreement",
            "KeyCertSign": "x509.ExtKeyUsageKeyCertSign",
            "CRLSign": "x509.ExtKeyUsageCRLSign",
            "EncipherOnly": "x509.ExtKeyUsageEncipherOnly",
            "DecipherOnly": "x509.ExtKeyUsageDecipherOnly",
        }
        bits_checks = []
        for bit in n.bits:
            if bit in _std_bits:
                bits_checks.append(f"util.HasEKU(c, {_std_bits[bit]})")
            else:
                ek = V.EKU_BY_NAME.get(bit)
                if ek is None:
                    raise dsl.DSLError(f"ExtKeyUsageAllBitsInSet: unknown EKU bit {bit!r}")
                bits_checks.append(f"util.HasEKU(c, {ek.go_expr})")
        all_checks = " && ".join(bits_checks)
        return _iife_bool([
            f"return {all_checks}",
        ])

    if isinstance(n, dsl.ExtKeyUsageCountInRange):
        # Check ExtKeyUsage extension entry count is within [lo, hi].
        # Counts both stdlib EKUs (c.ExtKeyUsage) and OID-based EKUs (c.UnknownExtKeyUsage).
        # Used for rules like 'anyExtendedKeyUsage must be the ONLY EKU when present'.
        hi = "math.MaxInt" if n.hi == "MAX_INT" else str(n.hi)
        return _iife_bool([
            "_eku_count := len(c.ExtKeyUsage) + len(c.UnknownExtKeyUsage)",
            f"return _eku_count >= {n.lo} && _eku_count <= {hi}",
        ])

    if isinstance(n, dsl.SerialNumberLengthInRange):
        # Check serial number byte length is within range
        if n.hi == "MAX_INT":
            return _iife_bool([
                f"return len(c.SerialNumber.Bytes) >= {n.lo}",
            ])
        return _iife_bool([
            f"_snLen := len(c.SerialNumber.Bytes)",
            f"return _snLen >= {n.lo} && _snLen <= {n.hi}",
        ])

    if isinstance(n, dsl.ExtHasAllGeneralNameTags):
        # Check SAN extension contains ALL required GeneralName tag types
        tags_checks = []
        for tag in n.required_tags:
            tags_checks.append(f"_hasTag_{tag}(c)")
        all_checks = " && ".join(tags_checks)
        return _iife_bool([f"return {all_checks}"])

    if isinstance(n, dsl.ExtHasAnyGeneralNameTags):
        # Check SAN extension contains AT LEAST ONE of the specified GeneralName tag types
        tags_checks = []
        for tag in n.allowed_tags:
            tags_checks.append(f"_hasTag_{tag}(c)")
        any_checks = " || ".join(tags_checks)
        return _iife_bool([f"return {any_checks}"])

    if isinstance(n, dsl.SubjectCommonNameMatchesSAN):
        # Check Subject CN matches at least one SAN entry
        return _iife_bool([
            "if c.Subject.CommonName == \"\" { return true }",
            "for _, name := range c.Subject.CommonNames {",
            "    if name == c.Subject.CommonName { return true }",
            "}",
            "return false",
        ])

    if isinstance(n, dsl.IssuerOrgMatchesSAN):
        # Check Issuer O field matches domain of a SAN entry
        return _iife_bool([
            "if c.Issuer.Organization == \"\" { return true }",
            "for _, name := range c.DNSNames {",
            "    if strings.Contains(name, c.Issuer.Organization) { return true }",
            "}",
            "return false",
        ])

    if isinstance(n, dsl.ExtAIAHasOCSPNoHTTP):
        # Check AIA OCSP responder URLs do NOT use HTTP scheme
        oid = V.OID_BY_NAME["AiaOID"].go_expr
        return _iife_bool([
            "_ext := util.GetExtFromCert(c, " + oid + ")",
            "if _ext == nil { return true }",
            "var _aia asn1.AuthorityInformationAccess",
            "if _, err := asn1.Unmarshal(_ext.Value, &_aia); err != nil { return false }",
            "for _, ad := range _aia {",
            "    if ad.Location.String != \"\" {",
            '        if strings.HasPrefix(ad.Location.String, "http://") { return false }',
            "    }",
            "}",
            "return true",
        ])

    if isinstance(n, dsl.ExtHasDuplicateGeneralNames):
        # Check SAN extension for duplicate GeneralName values
        oid = V.OID_BY_NAME["AiaOID"].go_expr  # Reuse - need SAN OID
        return _iife_bool([
            "var _seen = make(map[string]bool)",
            "for _, dns := range c.DNSNames {",
            "    if _seen[dns] { return true }",
            "    _seen[dns] = true",
            "}",
            "for _, email := range c.EmailAddresses {",
            "    if _seen[email] { return true }",
            "    _seen[email] = true",
            "}",
            "return false",
        ])

    if isinstance(n, dsl.ExtNotPresentOrHasProperty):
        # If extension is present, it must satisfy the property; vacuously true if absent
        oid = V.OID_BY_NAME.get(n.oid)
        if oid is None:
            raise dsl.DSLError(f"ExtNotPresentOrHasProperty: unknown OID {n.oid}")
        oid_expr = oid.go_expr
        inner = _emit(n.property, in_item=False, item_var=None)
        return _iife_bool([
            f"_ext := util.GetExtFromCert(c, {oid_expr})",
            "if _ext == nil { return true }",
            f"return {inner}",
        ])

    raise dsl.DSLError(f"renderer: unhandled node {type(n).__name__}")


# ---------------------------------------------------------------------
# Helpers for the new atoms
# ---------------------------------------------------------------------

def _emit_date_ref(d: str) -> str:
    """Emit either a DATE_FIELD's go_expr, or a Go time.Time literal for YYYY-MM-DD."""
    if d in V.DATE_BY_NAME:
        return V.DATE_BY_NAME[d].go_expr
    # YYYY-MM-DD literal -> time.Date(...)
    y, m, day = d.split("-")
    return f"time.Date({int(y)}, {int(m)}, {int(day)}, 0, 0, 0, 0, time.UTC)"


def _hex_literal(hex_str: str) -> str:
    """Emit a Go []byte literal from a hex string."""
    pairs = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]
    return "[]byte{" + ", ".join("0x" + p for p in pairs) + "}"


def _oid_to_der_hex(oid_expr: str) -> str:
    """Compile an OID Go literal/reference into DER hex (06 LL VV...).

    Accepts either:
      - inline literal: "asn1.ObjectIdentifier{1, 3, 132, 0, 34}"
      - util reference: "util.OidRSAEncryption" (look up in zlint util oid.go)

    Returns hex string like "06052b81040022" (06=OID tag, 05=length, 2b...=value).
    """
    import re
    m = re.search(r"\{([0-9,\s]+)\}", oid_expr)
    if m:
        arcs = [int(x.strip()) for x in m.group(1).split(",") if x.strip()]
    elif oid_expr.startswith("util."):
        # reference to a constant in zlint util — resolve from util/oid.go.
        # Lazy-load and cache the parse on first use.
        arcs = _UTIL_OID_ARCS.get(oid_expr.removeprefix("util."))
        if arcs is None:
            raise dsl.DSLError(
                f"_oid_to_der_hex: util constant '{oid_expr}' not found in cache")
    else:
        raise dsl.DSLError(f"_oid_to_der_hex: cannot parse OID expr {oid_expr!r}")

    # Encode OID arcs to DER content bytes: first byte = arc[0]*40 + arc[1].
    if len(arcs) < 2:
        raise dsl.DSLError(f"OID must have at least 2 arcs, got {arcs}")
    content = bytearray()
    content.append(arcs[0] * 40 + arcs[1])
    for arc in arcs[2:]:
        # base-128 encoding; high bit set on all but last byte
        if arc == 0:
            content.append(0)
            continue
        chunks = []
        v = arc
        while v > 0:
            chunks.append(v & 0x7f)
            v >>= 7
        for i, c in enumerate(reversed(chunks)):
            content.append(c | (0x80 if i < len(chunks) - 1 else 0))
    # OID DER: tag 06, length, content
    if len(content) > 127:
        raise dsl.DSLError("long-form length not supported (oid too long)")
    return f"06{len(content):02x}{''.join(f'{b:02x}' for b in content)}"


# Lazy-loaded map of util.X → arcs. Parsed from zlint util/oid.go on demand.
_UTIL_OID_ARCS: dict = {}

def _load_util_oid_arcs():
    """Parse zlint util/oid.go and util/algorithm_identifier.go for the OID
    constants referenced by util.X expressions."""
    import os, re as _re
    if _UTIL_OID_ARCS:
        return
    paths = [
        "/home/bernhard/projects/cicas/cicas_backend/zlint/v3/util/oid.go",
        "/home/bernhard/projects/cicas/cicas_backend/zlint/v3/util/algorithm_identifier.go",
    ]
    for p in paths:
        if not os.path.exists(p): continue
        with open(p) as f:
            text = f.read()
        for m in _re.finditer(
            r"(\w+)\s*=\s*asn1\.ObjectIdentifier\{([0-9,\s]+)\}", text):
            name = m.group(1)
            arcs = [int(x.strip()) for x in m.group(2).split(",") if x.strip()]
            _UTIL_OID_ARCS[name] = arcs

_load_util_oid_arcs()


# ---------------------------------------------------------------------
# Emit helpers per semantic class
# ---------------------------------------------------------------------

def _bigint_lit(v) -> str:
    """Emit a *big.Int literal. big.NewInt takes an int64, which overflows for
    values beyond ~9.2e18 (e.g. a 20-octet serialNumber upper bound 2^160, or
    large RSA exponents). For those, fall back to new(big.Int).SetString so the
    literal is constructed faithfully and the Go compiles."""
    if isinstance(v, int) and abs(v) <= (1 << 62):
        return f"big.NewInt({v})"
    return ('func() *big.Int { _v, _ := new(big.Int).SetString("'
            + str(int(v)) + '", 10); return _v }()')


def _emit_field_eq(f: V.FieldDef, rhs: str) -> str:
    if f.semantic in ("string", "int"):
        return f"({f.go_expr} == {rhs})"
    if f.semantic == "string_list":
        return (f"(len({f.go_expr}) == 1 && {f.go_expr}[0] == {rhs})")
    if f.semantic == "bigint":
        # rhs may be a huge serialNumber literal -> use SetString-safe emission.
        try:
            rhs_expr = _bigint_lit(int(rhs))
        except (TypeError, ValueError):
            rhs_expr = f"big.NewInt({rhs})"
        return f"({f.go_expr}.Cmp({rhs_expr}) == 0)"
    raise dsl.DSLError(
        f"FieldEq: unsupported semantic {f.semantic} for field '{f.name}'. "
        "Use FieldNonEmpty/FieldEmpty for bool fields.")


def _emit_field_nonempty(f: V.FieldDef) -> str:
    if f.name == "Version":
        return _emit_der_version_present()
    if f.semantic == "string":
        return f"({f.go_expr} != \"\")"
    if f.semantic in ("string_list", "ip_list", "oid_list",
                      "eku_list", "ext_list", "bytes", "subtree_list"):
        return f"(len({f.go_expr}) > 0)"
    if f.semantic == "int":
        return f"({f.go_expr} != 0)"
    if f.semantic == "bool":
        return f"({f.go_expr})"
    if f.semantic == "bigint":
        return f"({f.go_expr} != nil && {f.go_expr}.Sign() != 0)"
    if f.semantic == "time":
        return f"!{f.go_expr}.IsZero()"
    if f.semantic == "oid":
        return f"(len({f.go_expr}) > 0)"
    if f.semantic in ("keyusage_bits", "eku_list"):
        # KeyUsage and ExtKeyUsage bitsets: nonzero means at least one bit is set
        return f"({f.go_expr} != 0)"
    raise dsl.DSLError(f"FieldNonEmpty: unsupported semantic {f.semantic}")


def _emit_der_version_present() -> str:
    """True iff TBSCertificate carries the optional [0] EXPLICIT version field.

    zcrypto exposes c.Version after applying the ASN.1 default, so `c.Version != 0`
    is not a presence test: an omitted v1 version still becomes Version == 1.
    Rules that say "if present, version ..." need the raw DER tag.
    """
    return _iife_bool([
        "var _tbs asn1.RawValue",
        "if _, _err := asn1.Unmarshal(c.RawTBSCertificate, &_tbs); _err != nil { return false }",
        "_rest := _tbs.Bytes",
        "if len(_rest) == 0 { return false }",
        "var _first asn1.RawValue",
        "if _, _err := asn1.Unmarshal(_rest, &_first); _err != nil { return false }",
        "return _first.Class == asn1.ClassContextSpecific && _first.Tag == 0 && _first.IsCompound",
    ])


def _iife_bool(body_lines: list) -> str:
    """Wrap a sequence of Go statement lines into an IIFE returning bool.
    Uses real newlines (and tab indentation) so Go's automatic semicolon
    insertion handles it correctly when embedded in `if EXPR { ... }`."""
    inner = "\n".join("\t\t" + ln for ln in body_lines)
    return "func() bool {\n" + inner + "\n\t}()"


def _lookup_field(name: str) -> V.FieldDef:
    """Look up a field and raise a clear DSLError if unknown."""
    f = V.lookup_anyfield(name)
    if f is None:
        raise dsl.DSLError(
            f"Unknown field '{name}'; "
            f"check ir_to_dsl subject/predicate mapping or add to CERT_FIELDS/DN_FIELDS"
        )
    return f


# KeyUsage / EKU bit name normalization (prose/RFC spellings -> zcrypto/x509 constants).
# RFC nonRepudiation is exposed by zcrypto/x509 as ContentCommitment.
_BIT_ALIASES = {
    "any extended key usage": "Any",
    "anyextendedkeyusage": "Any",
    "anyeku": "Any",
    "digital signature": "DigitalSignature",
    "digitalsignature": "DigitalSignature",
    "nonrepudiation": "ContentCommitment",
    "non_repudiation": "ContentCommitment",
    "non repudiation": "ContentCommitment",
    "keyencipherment": "KeyEncipherment",
    "key encipherment": "KeyEncipherment",
    "dataencipherment": "DataEncipherment",
    "dataencipherment": "DataEncipherment",
    "keyagreement": "KeyAgreement",
    "key agreement": "KeyAgreement",
    "keycertsign": "CertSign",
    "key_cert_sign": "CertSign",
    "key cert sign": "CertSign",
    "crlsign": "CRLSign",
    "crl_sign": "CRLSign",
    "crl sign": "CRLSign",
    "encipheronly": "EncipherOnly",
    "encipher_only": "EncipherOnly",
    "decipheronly": "DecipherOnly",
    "decipher_only": "DecipherOnly",
    "server auth": "ServerAuth",
    "client auth": "ClientAuth",
    "code signing": "CodeSigning",
    "email protection": "EmailProtection",
    "time stamping": "TimeStamping",
    "ocsp signing": "OCSPSigning",
    "serverauth": "ServerAuth",
    "clientauth": "ClientAuth",
    "codesigning": "CodeSigning",
    "emailprotection": "EmailProtection",
    "timestamping": "TimeStamping",
    "ocspsigning": "OCSPSigning",
}

def _norm_bit_name(s: str) -> str:
    """Normalize a prose bit name to PascalCase zcrypto constant suffix.
    e.g. 'digitalSignature' -> 'DigitalSignature', 'nonRepudiation' -> 'NonRepudiation'."""
    s = s.strip()
    if s in V.KU_BY_NAME or s in V.EKU_BY_NAME:
        return s
    lower = s.lower()
    if lower in _BIT_ALIASES:
        return _BIT_ALIASES[lower]
    # Generic PascalCase: lowercase-first, uppercase each word boundary, strip spaces.
    # "digitalSignature" -> "DigitalSignature", "nonRepudiation" -> "NonRepudiation"
    import re
    words = re.split(r'[\s_-]+', s)
    canonical = "".join(w.capitalize() for w in words if w)
    return _BIT_ALIASES.get(canonical, canonical)


def _eku_allowed_exprs(bits: tuple) -> tuple[list[str], list[str]]:
    """Split EKU_BIT names into stdlib x509.ExtKeyUsage and OID expressions."""
    std_exprs: list[str] = []
    oid_exprs: list[str] = []
    for bit in bits:
        fd = V.EKU_BY_NAME.get(str(bit))
        if fd is None:
            raise dsl.DSLError(f"ExtKeyUsageOnlyHasUsagesInSet: unknown EKU bit {bit!r}")
        if fd.go_type == "x509.ExtKeyUsage":
            std_exprs.append(fd.go_expr)
        elif fd.go_type == "asn1.ObjectIdentifier":
            oid_exprs.append(fd.go_expr)
        else:
            raise dsl.DSLError(
                f"ExtKeyUsageOnlyHasUsagesInSet: unsupported EKU type {fd.go_type!r} for {bit!r}"
            )
    return std_exprs, oid_exprs


def _emit_eku_only_allowed(bits: tuple) -> str:
    std_exprs, oid_exprs = _eku_allowed_exprs(bits)
    lines: list[str] = []
    if std_exprs:
        std_cond = " || ".join(f"_eku == {expr}" for expr in std_exprs)
        lines.extend([
            "for _, _eku := range c.ExtKeyUsage {",
            f"\tif {std_cond} {{ continue }}",
            "\treturn false",
            "}",
        ])
    else:
        lines.append("if len(c.ExtKeyUsage) > 0 { return false }")
    if oid_exprs:
        oid_cond = " || ".join(f"_eku.Equal({expr})" for expr in oid_exprs)
        lines.extend([
            "for _, _eku := range c.UnknownExtKeyUsage {",
            f"\tif {oid_cond} {{ continue }}",
            "\treturn false",
            "}",
        ])
    else:
        lines.append("if len(c.UnknownExtKeyUsage) > 0 { return false }")
    lines.append("return true")
    return _iife_bool(lines)


def _oid_dotted(name: str) -> Optional[str]:
    """Look up a named OID in the vocab and return its dotted-decimal form, or None."""
    if name in V.OID_BY_NAME:
        return V.OID_BY_NAME[name]
    return None


def _emit_field_regex(f: V.FieldDef, pattern: str) -> str:
    # `pattern` is a NAMED_REGEX name (validated at parse time); look up
    # the literal regex string from the closed vocab table.
    if pattern not in V.NAMED_REGEXES:
        raise dsl.DSLError(f"FieldMatchesRegex: unknown named regex '{pattern}'")
    pat = _go_string(V.NAMED_REGEXES[pattern][0])
    if f.semantic == "string":
        return f"regexp.MustCompile({pat}).MatchString({f.go_expr})"
    if f.semantic == "string_list":
        return _iife_bool([
            f"_re := regexp.MustCompile({pat})",
            f"for _, _x := range {f.go_expr} {{",
            f"\tif !_re.MatchString(_x) {{ return false }}",
            f"}}",
            f"return len({f.go_expr}) > 0",
        ])
    raise dsl.DSLError(f"FieldMatchesRegex: unsupported semantic {f.semantic}")


def _emit_field_in_set(f: V.FieldDef, values: tuple, *, negate: bool) -> str:
    op = "!=" if negate else "=="
    join = "&&" if negate else "||"
    if f.semantic == "string":
        clauses = f" {join} ".join(
            f"{f.go_expr} {op} {_go_string(v)}" for v in values
        )
        return f"({clauses})"
    if f.semantic == "string_list":
        lits = ", ".join(_go_string(v) for v in values)
        if negate:
            return _iife_bool([
                f"_set := []string{{{lits}}}",
                f"for _, _x := range {f.go_expr} {{",
                f"\tfor _, _y := range _set {{",
                f"\t\tif _x == _y {{ return false }}",
                f"\t}}",
                f"}}",
                f"return true",
            ])
        else:
            return _iife_bool([
                f"_set := []string{{{lits}}}",
                f"for _, _x := range {f.go_expr} {{",
                f"\t_ok := false",
                f"\tfor _, _y := range _set {{",
                f"\t\tif _x == _y {{ _ok = true; break }}",
                f"\t}}",
                f"\tif !_ok {{ return false }}",
                f"}}",
                f"return len({f.go_expr}) > 0",
            ])
    if f.semantic == "int":
        clauses = f" {join} ".join(
            f"{f.go_expr} {op} {v}" for v in values
        )
        return f"({clauses})"
    # oid_list / eku_list: check if list contains any of the specified OID constants.
    # zcrypto's zlint library exposes these as []util.OID (or []int at the int level).
    # Strategy: convert each OID name to its dotted form, then check list containment.
    if f.semantic in ("oid_list", "eku_list", "ext_list", "subtree_list"):
        # Build Go OID constants and check if any list element matches.
        oid_exprs = []
        for v in values:
            # Try as int first (for raw integer OID components)
            try:
                oid_exprs.append(f"[]int{{{', '.join(str(int(v)) for v in (v if isinstance(v, list) else [int(v)]))}}}")
            except (ValueError, TypeError):
                # Named OID: look up in V.OID_BY_NAME
                oid_name = str(v)
                if oid_name in V.OID_BY_NAME:
                    dotted = V.OID_BY_NAME[oid_name]
                    parts = dotted.replace(".", ", ")
                    oid_exprs.append(f"[]int{{{parts}}}")
                else:
                    # Unknown OID name — can't render deterministically
                    raise dsl.DSLError(
                        f"FieldInSet: unknown OID name '{v}' in {f.name}; "
                        f"add it to OID_CONSTS / _EXTRA_OIDS in vocab.py"
                    )
        oid_set_expr = f"[][]int{{{', '.join(oid_exprs)}}}"
        if negate:
            return _iife_bool([
                f"_set := {oid_set_expr}",
                f"for _, _oid := range {f.go_expr} {{",
                f"\tfor _, _target := range _set {{",
                f"\t\tif oidsEqual(_oid, _target) {{ return false }}",
                f"\t}}",
                f"}}",
                f"return true",
            ])
        else:
            return _iife_bool([
                f"_set := {oid_set_expr}",
                f"for _, _oid := range {f.go_expr} {{",
                f"\tfor _, _target := range _set {{",
                f"\t\tif oidsEqual(_oid, _target) {{ return true }}",
                f"\t}}",
                f"}}",
                f"return false",
            ])
    # keyusage_bits: FieldInSet(KeyUsage, {DigitalSignature, KeyEncipherment})
    # means the KeyUsage bitmask includes at least one of those bits.
    if f.semantic == "keyusage_bits":
        if not values:
            raise dsl.DSLError(f"FieldInSet: empty values for keyusage_bits field {f.name}")
        bit_exprs = []
        for v in values:
            bit_normalized = _norm_bit_name(str(v))
            if bit_normalized not in V.KU_BY_NAME:
                raise dsl.DSLError(f"FieldInSet: unknown KEY_USAGE_BIT '{v}'")
            bit = V.KU_BY_NAME[bit_normalized].go_expr
            bit_exprs.append(f"(({f.go_expr} & {bit}) != 0)")
        if negate:
            return "!(" + " || ".join(bit_exprs) + ")"
        return "(" + " || ".join(bit_exprs) + ")"
    raise dsl.DSLError(f"FieldInSet: unsupported semantic {f.semantic}")


def _emit_field_len_range(f: V.FieldDef, lo: int, hi):
    if f.semantic == "string":
        target = f"len({f.go_expr})"
    elif f.semantic in ("string_list", "ip_list", "oid_list",
                        "eku_list", "ext_list", "bytes", "subtree_list"):
        target = f"len({f.go_expr})"
    elif f.semantic == "bigint":
        # octet length of the integer's big-endian encoding (e.g. serialNumber
        # MUST be <= 20 octets, RFC 5280 §4.1.2.2). .Bytes() is the minimal
        # big-endian magnitude; sound for non-negative integers.
        target = f"len({f.go_expr}.Bytes())"
    else:
        raise dsl.DSLError(f"FieldLenInRange: unsupported semantic {f.semantic}")

    hi_expr = "math.MaxInt" if hi == "MAX_INT" else str(hi)
    return f"({target} >= {lo} && {target} <= {hi_expr})"


def _emit_field_count(f, lo: int, hi):
    """Occurrence count of a list-valued field in [lo, hi] (cardinality).

    GENERAL + sound: only defined for list-semantic fields, where the count IS
    len(go_expr) (e.g. "at least one dNSName", "no more than one X" over a
    repeated field). For scalar / non-list fields the notion of an occurrence
    count is ambiguous (and counting duplicate *extensions* needs a c.Extensions
    scan, a different atom), so we refuse rather than emit wrong Go — the caller
    demotes to the LLM path. Driven by f.semantic, never per-rule.
    """
    if f is None:
        raise dsl.DSLError(
            f"FieldCount: field not in vocab, cannot determine semantic for cardinality")
    if f.semantic in ("string_list", "ip_list", "oid_list", "eku_list",
                      "ext_list", "subtree_list"):
        target = f"len({f.go_expr})"
        hi_expr = "math.MaxInt" if hi == "MAX_INT" else str(hi)
        return f"({target} >= {lo} && {target} <= {hi_expr})"
    raise dsl.DSLError(
        f"FieldCount: occurrence count only defined for list fields, not semantic {f.semantic}")


def _emit_field_numeric_range(f: V.FieldDef, lo: int, hi):
    hi_expr = "math.MaxInt" if hi == "MAX_INT" else str(hi)
    if f.semantic == "int":
        return f"({f.go_expr} >= {lo} && {f.go_expr} <= {hi_expr})"
    if f.semantic == "bigint":
        # use big.Int Cmp; SetString-safe for bounds beyond int64 (e.g. 2^160).
        hi_part = ("true"
                   if hi == "MAX_INT"
                   else f"{f.go_expr}.Cmp({_bigint_lit(hi)}) <= 0")
        return (f"({f.go_expr} != nil"
                f" && {f.go_expr}.Cmp({_bigint_lit(lo)}) >= 0"
                f" && {hi_part})")
    raise dsl.DSLError(f"FieldNumericInRange: unsupported semantic {f.semantic}")


_ASN1_CHARSET_REGEX = {
    # Permitted-charset regexes; True iff string is encodable as that ASN.1 type.
    # Approximation at the Go-string layer — zcrypto's convenience fields are
    # already decoded UTF-8, so we cannot recover the original tag and instead
    # check whether the value's character set is compatible with the type.
    "PrintableString":  r"^[A-Za-z0-9 '()+,\-./:=?]*$",
    "IA5String":        r"^[\x00-\x7f]*$",
    "VisibleString":    r"^[\x20-\x7e]*$",
    "NumericString":    r"^[0-9 ]*$",
    "UTF8String":       r"^[\x00-\x{10FFFF}]*$",   # always matches valid Go strings
    "UniversalString":  r"^[\x00-\x{10FFFF}]*$",
    "BMPString":        r"^[\x00-\x{FFFF}]*$",     # excludes supplementary planes
    "T61String":        r"^[\x00-\xff]*$",         # loose approximation
    "TeletexString":    r"^[\x00-\xff]*$",         # alias of T61String (same loose set)
}


def _emit_field_encoded_as(f: V.FieldDef, types: tuple) -> str:
    """Check that string field's character set matches one of the listed
    ASN.1 string types (regex approximation; see _ASN1_CHARSET_REGEX)."""
    missing = [t for t in types if t not in _ASN1_CHARSET_REGEX]
    if missing:
        # No character-set model for these types. Time tags (UTCTime/
        # GeneralizedTime) are unrecoverable once zcrypto has decoded the value
        # to time.Time; other non-string types likewise can't be charset-checked.
        # Clean DSLError → caller falls back (sound: we don't emit a bogus check).
        raise dsl.DSLError(
            f"FieldEncodedAs: no charset model for ASN.1 type(s) {missing} "
            f"(field '{f.name}'); not checkable at the decoded convenience-field layer")
    pats = [_ASN1_CHARSET_REGEX[t] for t in types]
    if f.semantic == "string":
        if len(pats) == 1:
            return f"regexp.MustCompile({_go_string(pats[0])}).MatchString({f.go_expr})"
        ors = " || ".join(
            f"regexp.MustCompile({_go_string(p)}).MatchString({f.go_expr})"
            for p in pats
        )
        return f"({ors})"
    if f.semantic == "string_list":
        re_list = ", ".join(f"regexp.MustCompile({_go_string(p)})" for p in pats)
        return _iife_bool([
            f"_res := []*regexp.Regexp{{{re_list}}}",
            f"for _, _x := range {f.go_expr} {{",
            f"\t_ok := false",
            f"\tfor _, _re := range _res {{",
            f"\t\tif _re.MatchString(_x) {{ _ok = true; break }}",
            f"\t}}",
            f"\tif !_ok {{ return false }}",
            f"}}",
            f"return len({f.go_expr}) > 0",
        ])
    raise dsl.DSLError(f"FieldEncodedAs: unsupported semantic {f.semantic}")


# ASN.1 universal-class tag numbers for string types (X.680). Used to check a
# field's ACTUAL encoded tag (not a charset approximation) by reading raw DER.
_ASN1_STRING_TAG = {
    "UTF8String": 12, "NumericString": 18, "PrintableString": 19,
    "TeletexString": 20, "T61String": 20, "IA5String": 22,
    "VisibleString": 26, "ISO646String": 26, "UniversalString": 28, "BMPString": 30,
}


def _emit_dn_values_encoded_as(dn: str, types: tuple) -> str:
    """Every attribute value in the Subject/Issuer DN is encoded with an ASN.1
    string tag in the allowed set.

    GENERAL + sound: reads the ACTUAL DER tag from c.RawSubject / c.RawIssuer
    (zcrypto decodes attribute values to Go strings and loses the original tag),
    by walking the RDNSequence DER manually. The allowed tag set is driven by the
    rule's ASN.1 types — no per-rule / per-attribute code."""
    raw = "c.RawSubject" if dn.lower() == "subject" else "c.RawIssuer"
    tags = sorted({_ASN1_STRING_TAG[t] for t in types if t in _ASN1_STRING_TAG})
    if not tags:
        raise dsl.DSLError(f"DN encoded-as: no ASN.1 string tag for types {types}")
    cases = ", ".join(str(t) for t in tags)
    return _iife_bool([
        f"if len({raw}) == 0 {{ return false }}",
        "var _outer asn1.RawValue",
        f"if _, _e := asn1.Unmarshal({raw}, &_outer); _e != nil {{ return false }}",
        "_rest := _outer.Bytes",
        "for len(_rest) > 0 {",
        "\tvar _rdn asn1.RawValue",
        "\tvar _e error",
        "\t_rest, _e = asn1.Unmarshal(_rest, &_rdn)",
        "\tif _e != nil { return false }",
        "\t_inner := _rdn.Bytes",
        "\tfor len(_inner) > 0 {",
        "\t\tvar _atv asn1.RawValue",
        "\t\t_inner, _e = asn1.Unmarshal(_inner, &_atv)",
        "\t\tif _e != nil { return false }",
        "\t\tvar _typ asn1.ObjectIdentifier",
        "\t\t_r2, _e2 := asn1.Unmarshal(_atv.Bytes, &_typ)",
        "\t\tif _e2 != nil { return false }",
        "\t\tvar _val asn1.RawValue",
        "\t\tif _, _e3 := asn1.Unmarshal(_r2, &_val); _e3 != nil { return false }",
        "\t\tif _val.Class != asn1.ClassUniversal { return false }",
        f"\t\tswitch _val.Tag {{ case {cases}: default: return false }}",
        "\t}",
        "}",
        "return true",
    ])


def _emit_dn_directorystring_encoded_as(dn: str, types: tuple) -> str:
    """Every DN attribute value whose X.520 syntax is DirectoryString is encoded
    with an ASN.1 string tag in the allowed set; attributes with a non-DirectoryString
    syntax are SKIPPED (the rule's "exceptions").

    Sound + general: walks RawSubject/RawIssuer DER, and for each AttributeTypeAndValue
    reads its type OID — only DirectoryString-syntax attributes are tag-checked. The
    non-DirectoryString OID set is the X.520 / RFC 5280 fixed list (countryName,
    domainComponent, emailAddress, serialNumber, dnQualifier), not per-rule."""
    raw = "c.RawSubject" if dn.lower() == "subject" else "c.RawIssuer"
    tags = sorted({_ASN1_STRING_TAG[t] for t in types if t in _ASN1_STRING_TAG})
    if not tags:
        raise dsl.DSLError(f"DNDirectoryStringValuesEncodedAs: no ASN.1 string tag for {types}")
    cases = ", ".join(str(t) for t in tags)
    # Non-DirectoryString attribute type OIDs (skip these): countryName 2.5.4.6,
    # serialNumber 2.5.4.5, dnQualifier 2.5.4.46, domainComponent 0.9.2342.19200300.100.1.25,
    # emailAddress 1.2.840.113549.1.9.1.
    return _iife_bool([
        f"if len({raw}) == 0 {{ return true }}",
        "_skip := map[string]bool{",
        '\t"2.5.4.6": true, "2.5.4.5": true, "2.5.4.46": true,',
        '\t"0.9.2342.19200300.100.1.25": true, "1.2.840.113549.1.9.1": true,',
        "}",
        "var _outer asn1.RawValue",
        f"if _, _e := asn1.Unmarshal({raw}, &_outer); _e != nil {{ return false }}",
        "_rest := _outer.Bytes",
        "for len(_rest) > 0 {",
        "\tvar _rdn asn1.RawValue",
        "\tvar _e error",
        "\t_rest, _e = asn1.Unmarshal(_rest, &_rdn)",
        "\tif _e != nil { return false }",
        "\t_inner := _rdn.Bytes",
        "\tfor len(_inner) > 0 {",
        "\t\tvar _atv asn1.RawValue",
        "\t\t_inner, _e = asn1.Unmarshal(_inner, &_atv)",
        "\t\tif _e != nil { return false }",
        "\t\tvar _typ asn1.ObjectIdentifier",
        "\t\t_r2, _e2 := asn1.Unmarshal(_atv.Bytes, &_typ)",
        "\t\tif _e2 != nil { return false }",
        "\t\tif _skip[_typ.String()] { continue }",  # non-DirectoryString attr → skip
        "\t\tvar _val asn1.RawValue",
        "\t\tif _, _e3 := asn1.Unmarshal(_r2, &_val); _e3 != nil { return false }",
        "\t\tif _val.Class != asn1.ClassUniversal { return false }",
        f"\t\tswitch _val.Tag {{ case {cases}: default: return false }}",
        "\t}",
        "}",
        "return true",
    ])


def _emit_list_iter(field_name: str, predicate, semantic: str) -> str:
    """semantic = 'all' or 'any'."""
    f = V.lookup_anyfield(field_name)
    item_var = "_item"
    inner = _emit(predicate, in_item=True, item_var=item_var)
    if semantic == "all":
        return _iife_bool([
            f"for _, {item_var} := range {f.go_expr} {{",
            f"\tif !({inner}) {{ return false }}",
            f"}}",
            f"return len({f.go_expr}) > 0",
        ])
    else:
        return _iife_bool([
            f"for _, {item_var} := range {f.go_expr} {{",
            f"\tif ({inner}) {{ return true }}",
            f"}}",
            f"return false",
        ])


def _emit_list_unique(f: V.FieldDef) -> str:
    if f.semantic in ("string_list",):
        return _iife_bool([
            f"_seen := map[string]bool{{}}",
            f"for _, _x := range {f.go_expr} {{",
            f"\tif _seen[_x] {{ return false }}",
            f"\t_seen[_x] = true",
            f"}}",
            f"return true",
        ])
    if f.semantic in ("ip_list",):
        return _iife_bool([
            f"_seen := map[string]bool{{}}",
            f"for _, _x := range {f.go_expr} {{",
            f"\tif _seen[_x.String()] {{ return false }}",
            f"\t_seen[_x.String()] = true",
            f"}}",
            f"return true",
        ])
    raise dsl.DSLError(f"ListUnique: unsupported semantic {f.semantic}")


# ---------------------------------------------------------------------
# Literal helpers
# ---------------------------------------------------------------------

def _go_literal(v, semantic: str) -> str:
    """Emit a Go literal for the given value, type-aware against semantic."""
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        if semantic == "int":
            try:
                return str(int(v))
            except ValueError:
                pass
        return _go_string(v)
    raise dsl.DSLError(f"_go_literal: bad value {v!r}")


def _go_string(s: str) -> str:
    """Render a Python str as a Go double-quoted string literal."""
    out = '"'
    for ch in s:
        if ch == '\\':
            out += '\\\\'
        elif ch == '"':
            out += '\\"'
        elif ch == '\n':
            out += '\\n'
        elif ch == '\r':
            out += '\\r'
        elif ch == '\t':
            out += '\\t'
        elif ord(ch) < 0x20 or ord(ch) > 0x7E:
            out += f'\\u{ord(ch):04x}'
        else:
            out += ch
    out += '"'
    return out


# ---------------------------------------------------------------------
# OID / bit helpers (used across emitters)
# ---------------------------------------------------------------------

def _contains_int(values: list, item_var: str) -> str:
    """Emit Go code checking whether an int variable is in a []int set literal."""
    lits = ", ".join(str(v) for v in values)
    return f"func(_x int) bool {{ for _, _v := range []int{{{lits}}} {{ if _v == _x {{ return true }} }}; return false }}()"


# ---------------------------------------------------------------------
# Import collection
# ---------------------------------------------------------------------

def _walk_imports(n, imps: set[str]):
    if isinstance(n, (dsl.And, dsl.Or)):
        for p in n.parts:
            _walk_imports(p, imps)
        return
    if isinstance(n, dsl.Not):
        _walk_imports(n.inner, imps)
        return
    if isinstance(n, dsl.When):
        _walk_imports(n.cond, imps)
        _walk_imports(n.main, imps)
        return

    needs_util = (
        dsl.ExtPresent, dsl.ExtCritical, dsl.ExtNotCritical,
        dsl.ExtKeyUsageHas, dsl.IsServerCert, dsl.IsSubCA, dsl.ExtHasGeneralNameWithTag,
        dsl.ExtHasAnyGeneralNameOfTag,
    )
    if isinstance(n, needs_util):
        imps.add("github.com/zmap/zlint/v3/util")
    if isinstance(n, dsl.ExtHasAnyGeneralNameOfTag):
        imps.add("encoding/asn1")
    if isinstance(n, dsl.ExtSubfieldPresent):
        imps.add("github.com/zmap/zlint/v3/util")
        imps.add("encoding/asn1")
    if isinstance(n, dsl.ExtKeyUsageOnlyHasUsagesInSet):
        for bit in n.bits:
            fd = V.EKU_BY_NAME.get(str(bit))
            if fd and "util." in fd.go_expr:
                imps.add("github.com/zmap/zlint/v3/util")
            if fd and "asn1." in fd.go_expr:
                imps.add("encoding/asn1")
    if isinstance(n, dsl.AIAAccessDescriptionCountInRange):
        imps.add("github.com/zmap/zlint/v3/util")
        imps.add("encoding/asn1")
        if n.hi == "MAX_INT" or (isinstance(n.hi, int) and n.hi > (1 << 62)):
            imps.add("math")
    if isinstance(n, dsl.AIAAccessLocationUniquePerMethod):
        imps.add("github.com/zmap/zlint/v3/util")
        imps.add("encoding/asn1")
    if isinstance(n, dsl.ExtensionURISchemeNotInSet):
        imps.add("encoding/asn1")

    if isinstance(n, dsl.SigAlgMatchesTBSSignature):
        imps.add("bytes")
        imps.add("golang.org/x/crypto/cryptobyte")
        imps.add("golang.org/x/crypto/cryptobyte/asn1")
    if isinstance(n, dsl.SignatureAlgorithmIdentifiersEqualHex):
        imps.add("bytes")
        imps.add("golang.org/x/crypto/cryptobyte")
        imps.add("golang.org/x/crypto/cryptobyte/asn1")
    if isinstance(n, dsl.SPKIAlgorithmIdentifierEqualsHex):
        imps.add("bytes")
        imps.add("golang.org/x/crypto/cryptobyte")
        imps.add("golang.org/x/crypto/cryptobyte/asn1")

    if isinstance(n, (dsl.FieldMatchesRegex, dsl.ItemMatchesRegex,
                      dsl.ItemNotMatchesRegex,
                      dsl.FieldNotMatchesRegex)):
        imps.add("regexp")
    if isinstance(n, (dsl.FieldNonEmpty, dsl.FieldEmpty)) and getattr(n, "field", None) == "Version":
        imps.add("encoding/asn1")
    if isinstance(n, dsl.FieldEncodedAs) and n.field not in ("Subject", "Issuer", "subject", "issuer"):
        imps.add("regexp")

    if isinstance(n, (dsl.FieldContains, dsl.WildcardFilter,
                      dsl.DNSNamesFQDNOrWildcardPortionMatchesRegex,
                      dsl.DNSOnionNamesHaveValidTorV3Address,
                      dsl.DomainNamesDoNotEndWithIPReverseZoneSuffix)):
        imps.add("strings")
    if isinstance(n, dsl.DNSNamesFQDNOrWildcardPortionMatchesRegex):
        imps.add("regexp")
    if isinstance(n, dsl.SubjectCommonNameFQDNOrWildcardPortionMatchesRegex):
        imps.add("net")
        imps.add("regexp")
        imps.add("strings")
    if isinstance(n, dsl.SubjectCommonNameFQDNMatchesDNSNameSAN):
        imps.add("net")
        imps.add("strings")
    if isinstance(n, dsl.WildcardFilter):
        # WildcardFilter wraps an inner predicate (often Item* atoms);
        # recurse so e.g. ItemMatchesRegex inside contributes "regexp".
        _walk_imports(n.predicate, imps)

    if isinstance(n, (dsl.IPv4Conditional, dsl.SubtreeIPv4Conditional)):
        _walk_imports(n.ipv4_predicate, imps)
        _walk_imports(n.ipv6_predicate, imps)

    if isinstance(n, dsl.FieldNumericInRange):
        f = V.lookup_anyfield(getattr(n, "field", ""))
        if f and f.semantic == "bigint":
            imps.add("math/big")              # big.NewInt(...) in the bigint path
        elif n.hi == "MAX_INT" or n.lo == "MAX_INT":
            imps.add("math")                  # math.MaxInt in the int path
    if isinstance(n, dsl.FieldLenInRange):
        # len()-based for every semantic (bigint uses .Bytes(), no math/big).
        # Only math.MaxInt is needed, and only for an unbounded upper bound.
        if n.hi == "MAX_INT" or n.lo == "MAX_INT":
            imps.add("math")

    if isinstance(n, dsl.FieldCount):
        # len()-based occurrence count; math.MaxInt only for an unbounded upper bound.
        if n.hi == "MAX_INT" or n.lo == "MAX_INT":
            imps.add("math")

    if isinstance(n, dsl.RSAModulusBitsInRange):
        imps.add("github.com/zmap/zcrypto/rsa")  # zcrypto stores keys as ITS rsa.PublicKey, not stdlib
        if n.hi == "MAX_INT" or (isinstance(n.hi, int) and n.hi > (1 << 62)):
            imps.add("math")
    if isinstance(n, dsl.RSAPublicExponentInRange):
        imps.add("github.com/zmap/zcrypto/rsa")
        imps.add("math/big")  # E is *big.Int -> Cmp/big.NewInt/SetString
    if isinstance(n, dsl.SerialNumberDERSignBitZero):
        imps.add("encoding/asn1")

    if isinstance(n, dsl.FieldEncodedAs) and n.field in ("Subject", "Issuer", "subject", "issuer"):
        # whole-DN encoded-as reads raw DER tags via encoding/asn1.
        imps.add("encoding/asn1")

    if isinstance(n, dsl.DNDirectoryStringValuesEncodedAs):
        # per-attribute DN encoded-as walks the RDNSequence DER via encoding/asn1.
        imps.add("encoding/asn1")
    if isinstance(n, (dsl.DNHasRDNSequence, dsl.RDNHasSingleAttribute, dsl.RDNSequenceHasCountryBefore)):
        imps.add("encoding/asn1")

    if isinstance(n, dsl.FieldEq):
        f = V.lookup_anyfield(n.field)
        if f and f.semantic == "bigint":
            imps.add("math/big")

    if isinstance(n, dsl.CrossFieldEq):
        fa = V.lookup_anyfield(n.field_a)
        if fa and fa.semantic == "bytes":
            imps.add("bytes")

    if isinstance(n, (dsl.DateAfter,)):
        # `time` import is only needed when one of the date refs is `time.Now()`.
        if n.later == "now" or n.earlier == "now":
            imps.add("time")

    if isinstance(n, (dsl.ListAllMatch, dsl.ListAnyMatch)):
        _walk_imports(n.predicate, imps)
    if isinstance(n, (dsl.SubtreeStringListAllMatch, dsl.SubtreeStringListAnyMatch,
                       dsl.SubtreeStringListAllMatchOrEmpty)):
        _walk_imports(n.predicate, imps)
    if isinstance(n, (dsl.NameConstraintsExcludedSubtreesEmpty,
                      dsl.NameConstraintsPermittedSubtreesNonEmpty)):
        imps.add("encoding/asn1")
        imps.add("github.com/zmap/zlint/v3/util")

    if isinstance(n, dsl.BytesEq):
        imps.add("bytes")
    if isinstance(n, dsl.OidListContains):
        # util.* OID consts need util; inline asn1 literals are rendered as a
        # .String() dotted-decimal compare (no asn1 import needed).
        _ge = V.OID_BY_NAME[n.oid].go_expr if n.oid in V.OID_BY_NAME else ""
        if "util." in _ge:
            imps.add("github.com/zmap/zlint/v3/util")
    if isinstance(n, dsl.OidListCountInSet):
        for _o in n.allowed_oids:
            _ge = V.OID_BY_NAME[_o].go_expr if _o in V.OID_BY_NAME else ""
            if "util." in _ge:
                imps.add("github.com/zmap/zlint/v3/util")
        if n.hi == "MAX_INT":
            imps.add("math")
    if isinstance(n, dsl.DateBefore):
        imps.add("time")
    if isinstance(n, (dsl.BytesEqualsHex, dsl.BytesContainsHex)):
        imps.add("bytes")
    if isinstance(n, (dsl.ExtRawValueEqualsHex, dsl.ExtRawValueContainsHex)):
        imps.add("bytes")
        imps.add("github.com/zmap/zlint/v3/util")
    if isinstance(n, dsl.BasicConstraintsCAFalseEncodedAsEmptySequence):
        imps.add("bytes")
        imps.add("encoding/asn1")
        imps.add("github.com/zmap/zlint/v3/util")
    if isinstance(n, (dsl.AIAHasMethodOtherThan, dsl.AIAMethodLocationsTagInSet,
                      dsl.AIAMethodLocationsAnyMatchRegex)):
        imps.add("encoding/asn1")
        imps.add("github.com/zmap/zlint/v3/util")
    if isinstance(n, dsl.AIAMethodLocationsAnyMatchRegex):
        imps.add("regexp")
    if isinstance(n, (dsl.CRLDPHasNameRelative,
                      dsl.CRLDPHasNameRelativeWithMultiIssuer)):
        imps.add("encoding/asn1")
    if isinstance(n, dsl.ValidityDateAsn1TagInSet):
        imps.add("encoding/asn1")
    if isinstance(n, dsl.ValidityUTCTimeValuesUseZulu):
        imps.add("encoding/asn1")
    if isinstance(n, (dsl.CertPolicyExplicitTextHasEncodingTagInSet,
                      dsl.CertPolicyExplicitTextAllHaveEncodingTagInSet)):
        imps.add("encoding/asn1")
    if isinstance(n, (dsl.PolicyQualifierOIDInSet, dsl.PolicyQualifierOIDNotInSet)):
        imps.add("encoding/asn1")
        imps.add("bytes")
    if isinstance(n, (dsl.ExtPolicyQualifierOIDInSet, dsl.ExtPolicyQualifierOIDNotInSet,
                      dsl.CertificatePoliciesHasNoPolicyQualifiers)):
        imps.add("encoding/asn1")
        imps.add("github.com/zmap/zlint/v3/util")
    if isinstance(n, dsl.OidEq):
        _ge = V.OID_BY_NAME[n.oid].go_expr if n.oid in V.OID_BY_NAME else ""
        if "util." in _ge:
            imps.add("github.com/zmap/zlint/v3/util")
    if isinstance(n, dsl.BytesContainsOidDer):
        imps.add("bytes")
    # IPListVersionAllOctetCount / SubtreeIPListAnyHasOctetCount /
    # SubtreeIPListVersionAllOctetCount / SubtreeIPVersionMaskValidCIDR:
    # no extra imports needed (operate on already-typed IP/subtree values
    # and inline len()/To4()/bit tests).


def _walk_vocab(n, out: dict):
    def bump(d, k): d[k] = d.get(k, 0) + 1
    if isinstance(n, (dsl.And, dsl.Or)):
        for p in n.parts: _walk_vocab(p, out)
    elif isinstance(n, dsl.Not):
        _walk_vocab(n.inner, out)
    elif isinstance(n, (dsl.ExtPresent, dsl.ExtCritical, dsl.ExtNotCritical)):
        bump(out, "oids")
    elif isinstance(n, (dsl.KeyUsageHas, dsl.KeyUsageOnlyHasBitsInSet)):
        bump(out, "ku_bits")
    elif isinstance(n, dsl.ExtKeyUsageHas):
        bump(out, "eku_bits")
    elif isinstance(n, dsl.ExtKeyUsageOnlyHasUsagesInSet):
        bump(out, "eku_bits")
    elif isinstance(n, dsl.ExtKeyUsageHasBit):
        bump(out, "eku_bits")
    elif isinstance(n, dsl.ExtKeyUsageNotHasBit):
        bump(out, "eku_bits")
    elif isinstance(n, dsl.ExtKeyUsageAllBitsInSet):
        bump(out, "eku_bits")
    elif isinstance(n, dsl.ExtKeyUsageCountInRange):
        pass  # no vocab import needed
    elif isinstance(n, (dsl.FieldEq, dsl.FieldNonEmpty, dsl.FieldEmpty,
                        dsl.FieldMatchesRegex, dsl.FieldInSet, dsl.FieldNotInSet,
                        dsl.FieldLenInRange, dsl.FieldNumericInRange)):
        bump(out, "fields")
    elif isinstance(n, dsl.FieldEncodedAs):
        bump(out, "fields")
        for t in n.types: bump(out, "asn1_types")
    elif isinstance(n, dsl.DateAfter):
        bump(out, "dates")
        bump(out, "dates")
    elif isinstance(n, (dsl.ListAllMatch, dsl.ListAnyMatch)):
        bump(out, "fields")
        _walk_vocab(n.predicate, out)
    elif isinstance(n, dsl.ListUnique):
        bump(out, "fields")
    elif isinstance(n, dsl.BytesEq):
        bump(out, "fields")
        bump(out, "fields")
    elif isinstance(n, dsl.IPListAllOctetCount):
        bump(out, "fields")
    elif isinstance(n, dsl.IPListVersionAllOctetCount):
        bump(out, "fields")
    elif isinstance(n, dsl.OidListContains):
        bump(out, "fields")
        bump(out, "oids")
    elif isinstance(n, dsl.DateBefore):
        # only bump if real DATE_FIELD; literals don't go in vocab
        if n.earlier in dsl.V.DATE_BY_NAME:
            bump(out, "dates")
        if n.later in dsl.V.DATE_BY_NAME:
            bump(out, "dates")
    elif isinstance(n, (dsl.BytesEqualsHex, dsl.BytesContainsHex)):
        bump(out, "fields")
    elif isinstance(n, (dsl.ExtRawValueEqualsHex, dsl.ExtRawValueContainsHex)):
        bump(out, "oids")
    elif isinstance(n, dsl.AIAHasMethodOtherThan):
        bump(out, "oids")  # ext_oid
        for _ in n.allowed_oids: bump(out, "oids")
    elif isinstance(n, (dsl.AIAMethodLocationsTagInSet,
                        dsl.AIAMethodLocationsAnyMatchRegex)):
        bump(out, "oids")  # ext_oid
        bump(out, "oids")  # method_oid
    elif isinstance(n, (dsl.CRLDPHasNameRelative,
                        dsl.CRLDPHasNameRelativeWithMultiIssuer)):
        bump(out, "oids")  # OidExtCrlDistributionPoints (implicit)
    elif isinstance(n, dsl.ValidityDateAsn1TagInSet):
        for _ in n.allowed_tags: bump(out, "asn1_types")
    elif isinstance(n, dsl.CertPolicyExplicitTextHasEncodingTagInSet):
        bump(out, "oids")  # CertPolicyOID + UserNoticeOID (implicit)
        for _ in n.allowed_tags: bump(out, "asn1_types")
    elif isinstance(n, (dsl.PolicyQualifierOIDInSet, dsl.PolicyQualifierOIDNotInSet)):
        bump(out, "oids")  # PolicyQualifierOID
    elif isinstance(n, dsl.AlgorithmIdentifierBytesMatch):
        bump(out, "oids")  # oid_const
    elif isinstance(n, dsl.OidEq):
        bump(out, "fields")
        bump(out, "oids")
    elif isinstance(n, dsl.SubtreeIPListAnyHasOctetCount):
        bump(out, "fields")
    elif isinstance(n, dsl.SubtreeIPListVersionAllOctetCount):
        bump(out, "fields")
    elif isinstance(n, dsl.BytesContainsOidDer):
        bump(out, "fields")
        bump(out, "oids")
    elif isinstance(n, dsl.IPListAllOctetCountIn):
        bump(out, "fields")
    elif isinstance(n, dsl.SubtreeIPListAnyAllZero):
        bump(out, "fields")
    elif isinstance(n, dsl.SubtreeIPListAnyHasOctetCountAndNotAllZero):
        bump(out, "fields")
    elif isinstance(n, (dsl.SubtreeStringListAllMatch, dsl.SubtreeStringListAnyMatch,
                         dsl.SubtreeStringListAllMatchOrEmpty)):
        bump(out, "fields")
        _walk_vocab(n.predicate, out)
    elif isinstance(n, (dsl.SubtreeStringListHasNonEmptyOrEmptyMarker,
                        dsl.SubtreeStringListHasEmptyMarker)):
        bump(out, "fields")
    elif isinstance(n, dsl.NameConstraintsExcludedSubtreesEmpty):
        bump(out, "oids")
    elif isinstance(n, dsl.NameConstraintsPermittedSubtreesNonEmpty):
        bump(out, "oids")
    elif isinstance(n, dsl.SubtreeIPListAllOctetCountIn):
        bump(out, "fields")
    elif isinstance(n, dsl.SubtreeIPMaskValidCIDR):
        bump(out, "fields")
    elif isinstance(n, dsl.SubtreeIPVersionMaskValidCIDR):
        bump(out, "fields")
    elif isinstance(n, dsl.FieldContains):
        bump(out, "fields")
    elif isinstance(n, dsl.FieldNotMatchesRegex):
        bump(out, "fields")
    elif isinstance(n, dsl.CrossFieldEq):
        bump(out, "fields")
        bump(out, "fields")
    elif isinstance(n, dsl.ListSubsetOfList):
        bump(out, "fields")
        bump(out, "fields")
    elif isinstance(n, dsl.WildcardFilter):
        bump(out, "fields")
        _walk_vocab(n.predicate, out)
    elif isinstance(n, dsl.IPv4Conditional):
        bump(out, "fields")
        _walk_vocab(n.ipv4_predicate, out)
        _walk_vocab(n.ipv6_predicate, out)
    elif isinstance(n, dsl.SubtreeIPv4Conditional):
        bump(out, "fields")
        _walk_vocab(n.ipv4_predicate, out)
        _walk_vocab(n.ipv6_predicate, out)
    elif isinstance(n, dsl.ExtHasGeneralNameWithTag):
        bump(out, "oids")
    elif isinstance(n, dsl.ExtHasAnyGeneralNameOfTag):
        bump(out, "oids")
    elif isinstance(n, dsl.CertificatePoliciesHasNoPolicyQualifiers):
        bump(out, "oids")  # implicit CertPolicyOID
        return
    elif isinstance(n, dsl.ExtPolicyQualifierOIDInSet):
        bump(out, "oids")  # implicit CertPolicyOID
        for _ in n.allowed_oid_consts:
            bump(out, "oids")
        return
    elif isinstance(n, dsl.ExtPolicyQualifierOIDNotInSet):
        bump(out, "oids")  # implicit CertPolicyOID
        bump(out, "oids")
        return

    # ---- ExtPolicyQualifierOIDInSet ----
    if isinstance(n, dsl.ExtPolicyQualifierOIDInSet):
        import re as _re
        conds = []
        for oid_const in n.allowed_oid_consts:
            if oid_const in V.OID_BY_NAME:
                oid_field = V.OID_BY_NAME[oid_const]
                oid_expr = oid_field.go_expr
                if oid_expr.startswith("asn1.ObjectIdentifier{"):
                    arcs = ",".join(_re.findall(r"\d+", oid_expr))
                    oid_lit = f"asn1.ObjectIdentifier{{{arcs}}}"
                    conds.append(f"_q.PolicyQualifierId.Equal({oid_lit})")
                else:
                    dotted = ".".join(_re.findall(r"\d+", oid_expr))
                    conds.append(f'_q.PolicyQualifierId.String() == "{dotted}"')
            else:
                conds.append(f'_q.PolicyQualifierId.String() == "{oid_const}"')
        cond = " || ".join(conds) if conds else "false"
        return _iife_bool([
            "var _ev []byte",
            "for _, _ext := range c.Extensions {",
            "\tif len(_ext.Id) == 4 && _ext.Id[0] == 2 && _ext.Id[1] == 5 && _ext.Id[2] == 29 && _ext.Id[3] == 32 {",
            "\t\t_ev = _ext.Value; break",
            "\t}",
            "}",
            "if _ev == nil { return false }",
            "type _pqi struct {",
            "\tPolicyQualifierId asn1.ObjectIdentifier",
            "\tQualifier         asn1.RawValue",
            "}",
            "type _pi struct {",
            "\tPolicyIdentifier asn1.ObjectIdentifier",
            "\tPolicyQualifiers []_pqi `asn1:\"optional\"`",
            "}",
            "var _pis []_pi",
            "if _, _err := asn1.Unmarshal(_ev, &_pis); _err != nil { return false }",
            "for _, _p := range _pis {",
            "\tfor _, _q := range _p.PolicyQualifiers {",
            f"\t\tif {cond} {{ return true }}",
            "\t}",
            "}",
            "return false",
        ])

    if isinstance(n, dsl.ExtPolicyQualifierOIDNotInSet):
        import re as _re
        oid_const = n.forbidden_oid_const
        if oid_const in V.OID_BY_NAME:
            oid_field = V.OID_BY_NAME[oid_const]
            oid_expr = oid_field.go_expr
            if oid_expr.startswith("asn1.ObjectIdentifier{"):
                arcs = ",".join(_re.findall(r"\d+", oid_expr))
                oid_lit = f"asn1.ObjectIdentifier{{{arcs}}}"
                oid_compare = f"_q.PolicyQualifierId.Equal({oid_lit})"
            else:
                dotted = ".".join(_re.findall(r"\d+", oid_expr))
                oid_lit = f'"{dotted}"'
                oid_compare = f'_q.PolicyQualifierId.String() == {oid_lit}'
        else:
            oid_lit = f'"{oid_const}"'
            oid_compare = f'_q.PolicyQualifierId.String() == {oid_lit}'
        return _iife_bool([
            "var _ev []byte",
            "for _, _ext := range c.Extensions {",
            "\tif len(_ext.Id) == 4 && _ext.Id[0] == 2 && _ext.Id[1] == 5 && _ext.Id[2] == 29 && _ext.Id[3] == 32 {",
            "\t\t_ev = _ext.Value; break",
            "\t}",
            "}",
            "if _ev == nil { return true }",
            "type _pqi struct {",
            "\tPolicyQualifierId asn1.ObjectIdentifier",
            "\tQualifier         asn1.RawValue",
            "}",
            "type _pi struct {",
            "\tPolicyIdentifier asn1.ObjectIdentifier",
            "\tPolicyQualifiers []_pqi `asn1:\"optional\"`",
            "}",
            "var _pis []_pi",
            "if _, _err := asn1.Unmarshal(_ev, &_pis); _err != nil { return true }",
            "for _, _p := range _pis {",
            "\tfor _, _q := range _p.PolicyQualifiers {",
            f"\t\tif {oid_compare} {{ return false }}",
            "\t}",
            "}",
            "return true",
        ])

    # ---- ExtKeyUsageHasBit ----
    if isinstance(n, dsl.ExtKeyUsageHasBit):
        bit = _norm_bit_name(n.bit)
        return f"(c.KeyUsage&x509.{bit}) != 0"

    if isinstance(n, dsl.ExtKeyUsageNotHasBit):
        bit = _norm_bit_name(n.bit)
        return f"(c.KeyUsage&x509.{bit}) == 0"

    if isinstance(n, dsl.ExtKeyUsageAllBitsInSet):
        bits_expr = " | ".join(f"x509.{_norm_bit_name(b)}" for b in n.bits)
        return f"(c.KeyUsage & {bits_expr}) == {bits_expr}"

    if isinstance(n, dsl.ExtKeyUsageOnlyHasUsagesInSet):
        return _emit_eku_only_allowed(n.bits)

    # ---- SerialNumberLengthInRange ----
    if isinstance(n, dsl.SerialNumberLengthInRange):
        hi = "math.MaxInt" if n.hi == "MAX_INT" else str(n.hi)
        return _iife_bool([
            "if c.SerialNumber == nil { return true }",
            f"return c.SerialNumber.BitLen()/8 >= {n.lo} && c.SerialNumber.BitLen()/8 <= {hi}",
        ])

    # ---- ExtHasAllGeneralNameTags / ExtHasAnyGeneralNameTags ----
    if isinstance(n, dsl.ExtHasAllGeneralNameTags):
        # Get the SAN extension value
        return _iife_bool([
            "var _ev []byte",
            "for _, _ext := range c.Extensions {",
            "\tif _ext.Id.String() == \"2.5.29.17\" { _ev = _ext.Value; break }",
            "}",
            "if _ev == nil { return false }",
            "type _gn asn1.RawValue",
            "var _gns []_gn",
            "if _, _err := asn1.Unmarshal(_ev, &_gns); _err != nil { return false }",
            "for _, _g := range _gns {",
            f"\tif _g.Class == asn1.ClassContextSpecific && (_g.Tag == {n.required_tags[0]}",
            *(f" || _g.Tag == {t}" for t in n.required_tags[1:]),
            ") { return true }",
            "}",
            "return false",
        ])

    if isinstance(n, dsl.ExtHasAnyGeneralNameTags):
        tags = " || ".join(f"_g.Tag == {t}" for t in n.allowed_tags)
        return _iife_bool([
            "var _ev []byte",
            "for _, _ext := range c.Extensions {",
            "\tif _ext.Id.String() == \"2.5.29.17\" { _ev = _ext.Value; break }",
            "}",
            "if _ev == nil { return false }",
            "type _gn asn1.RawValue",
            "var _gns []_gn",
            "if _, _err := asn1.Unmarshal(_ev, &_gns); _err != nil { return false }",
            "for _, _g := range _gns {",
            f"\tif _g.Class == asn1.ClassContextSpecific && ({tags}) {{ return true }}",
            "}",
            "return false",
        ])

    # ---- SubjectCommonNameMatchesSAN ----
    if isinstance(n, dsl.SubjectCommonNameMatchesSAN):
        return _iife_bool([
            "var _cn string",
            "for _, _rdn := range c.Subject.Names {",
            "\tfor _, _tv := range _rdn.TypeAndValue {",
            '\t\tif _tv.Type.String() == "2.5.4.3" { _cn = _tv.Value.(string); break }',
            "\t}",
            "}",
            "if _cn == \"\" { return false }",
            "for _, _ext := range c.Extensions {",
            "\tif _ext.Id.String() == \"2.5.29.17\" {",
            "\t\ttype _gn asn1.RawValue",
            "\t\tvar _gns []_gn",
            "\t\tif _, _err := asn1.Unmarshal(_ext.Value, &_gns); _err != nil { continue }",
            "\t\tfor _, _g := range _gns {",
            '\t\t\tif _g.Tag == 2 && _g.Class == asn1.ClassContextSpecific && _g.Bytes != nil {',
            '\t\t\t\tif string(_g.Bytes) == _cn { return true }',
            "\t\t\t}",
            "\t\t}",
            "\t}",
            "}",
            "return false",
        ])

    # ---- IssuerOrgMatchesSAN ----
    if isinstance(n, dsl.IssuerOrgMatchesSAN):
        return _iife_bool([
            "var _org string",
            "for _, _rdn := range c.Issuer.Names {",
            "\tfor _, _tv := range _rdn.TypeAndValue {",
            '\t\tif _tv.Type.String() == "2.5.4.10" { _org = _tv.Value.(string); break }',
            "\t}",
            "}",
            "if _org == \"\" { return false }",
            "for _, _ext := range c.Extensions {",
            "\tif _ext.Id.String() == \"2.5.29.17\" {",
            "\t\ttype _gn asn1.RawValue",
            "\t\tvar _gns []_gn",
            "\t\tif _, _err := asn1.Unmarshal(_ext.Value, &_gns); _err != nil { continue }",
            "\t\tfor _, _g := range _gns {",
            '\t\t\tif _g.Tag == 2 && _g.Class == asn1.ClassContextSpecific && _g.Bytes != nil {',
            '\t\t\t\t_san := string(_g.Bytes)',
            "\t\t\t\tfor _i := len(_san)-1; _i >= 0; _i-- {",
            "\t\t\t\t\tif _san[_i] == '.' {",
            "\t\t\t\t\t\tif _san[_i+1:] == _org { return true }",
            "\t\t\t\t\t\tbreak",
            "\t\t\t\t\t}",
            "\t\t\t\t}",
            "\t\t\t}",
            "\t\t}",
            "\t}",
            "}",
            "return false",
        ])

    # ---- ExtAIAHasOCSPNoHTTP ----
    if isinstance(n, dsl.ExtAIAHasOCSPNoHTTP):
        return _iife_bool([
            "var _ev []byte",
            "for _, _ext := range c.Extensions {",
            "\tif _ext.Id.String() == \"1.3.6.1.5.5.7.1.1\" { _ev = _ext.Value; break }",  # AIA OID
            "}",
            "if _ev == nil { return false }",
            "type _aiadesc struct {",
            "\tMethod asn1.ObjectIdentifier",
            "\tLocation asn1.RawValue `asn1:\"tag:optional\"`",
            "}",
            "var _ais []_aiadesc",
            "if _, _err := asn1.Unmarshal(_ev, &_ais); _err != nil { return false }",
            "for _, _ai := range _ais {",
            '\t\tif _ai.Method.String() == "1.3.6.1.5.5.7.3.1" {',  # OCSP OID
            "\t\t\tif len(_ai.Location.Bytes) > 7 {",
            '\t\t\t\tif string(_ai.Location.Bytes[:7]) == "http://" { return false }',
            "\t\t\t}",
            "\t\t}",
            "}",
            "return true",
        ])

    # ---- ExtHasDuplicateGeneralNames ----
    if isinstance(n, dsl.ExtHasDuplicateGeneralNames):
        return _iife_bool([
            "var _ev []byte",
            "for _, _ext := range c.Extensions {",
            "\tif _ext.Id.String() == \"2.5.29.17\" { _ev = _ext.Value; break }",
            "}",
            "if _ev == nil { return false }",
            "type _gn asn1.RawValue",
            "var _gns []_gn",
            "if _, _err := asn1.Unmarshal(_ev, &_gns); _err != nil { return false }",
            "var _seen = make(map[string]bool)",
            "for _, _g := range _gns {",
            "\tif _g.Bytes == nil { continue }",
            "\t_val := string(_g.Bytes)",
            "\tif _seen[_val] { return true }",
            "\t_seen[_val] = true",
            "}",
            "return false",
        ])

    # ---- ExtNotPresentOrHasProperty ----
    if isinstance(n, dsl.ExtNotPresentOrHasProperty):
        oid = V.OID_BY_NAME[n.oid].go_expr
        inner = _emit(n.property, in_item=False, item_var=None)
        return _iife_bool([
            f"_e := util.GetExtFromCert(c, {oid})",
            "if _e == nil { return true }",
            f"return {inner}",
        ])

    # DomainComponentOrdered: no fields/oids/dates


# ---------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------

if __name__ == "__main__":
    sample = {
        "op": "And",
        "args": [
            {"op": "ExtPresent",   "args": ["CertPolicyOID"]},
            {"op": "ExtCritical",  "args": ["CertPolicyOID"]},
            {"op": "FieldNonEmpty","args": ["Subject.Province"]},
        ],
    }
    n = dsl.parse(sample)
    print("=== rule: ExtPresent(CertPolicyOID) AND Critical AND Subject.Province nonempty")
    print("Go:", render(n))
    print("imports:", sorted(collect_imports(n)))

    print()
    sample2 = {"op": "FieldEq",
               "args": ["Subject.CommonName", "example.com"]}
    n2 = dsl.parse(sample2)
    print("=== rule: Subject.CommonName == 'example.com'")
    print("Go:", render(n2))

    print()
    sample3 = {"op": "ListAllMatch", "args": [
        "DNSNames",
        {"op": "ItemMatchesRegex",
         "args": ["^[a-zA-Z0-9.-]+$"]}]}
    n3 = dsl.parse(sample3)
    print("=== rule: all DNSNames match LDH-ish regex")
    print("Go:", render(n3))
    print("imports:", sorted(collect_imports(n3)))

    print()
    sample4 = {"op": "FieldNumericInRange",
               "args": ["SerialNumber", 1, "MAX_INT"]}
    n4 = dsl.parse(sample4)
    print("=== rule: SerialNumber > 0")
    print("Go:", render(n4))
    print("imports:", sorted(collect_imports(n4)))

    print()
    sample5 = {"op": "FieldEncodedAs",
               "args": ["Subject.CommonName", ["PrintableString", "UTF8String"]]}
    n5 = dsl.parse(sample5)
    print("=== rule: CN encoded as PrintableString or UTF8String")
    print("Go:", render(n5))
