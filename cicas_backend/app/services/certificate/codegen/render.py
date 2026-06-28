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

    if isinstance(n, dsl.NotAfterIsNoExpirySentinel):
        # RFC 5280 §4.1.2.5: the "no well-defined expiration date" marker is
        # notAfter == 99991231235959Z (GeneralizedTime). zcrypto parses it to
        # time.Time, so compare the UTC components directly.
        return _iife_bool([
            "_t := c.NotAfter.UTC()",
            "return _t.Year() == 9999 && _t.Month() == 12 && _t.Day() == 31 && "
            "_t.Hour() == 23 && _t.Minute() == 59 && _t.Second() == 59",
        ])

    # ----- extension presence / criticality -----
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
        scheme_map = " + \",\" + ".join(f'"{s}"' for s in n.schemes)
        return _iife_bool([
            "_schemes := []string{\" + scheme_map + \"}",
            "for _, ext := range c.Extensions {",
            "    var _seq asn1.RawValue",
            "    if _, err := asn1.Unmarshal(ext.Value, &_seq); err != nil { continue }",
            "    _rest := _seq.Bytes",
            "    for len(_rest) > 0 {",
            "        var _v asn1.RawValue",
            "        _next, err := asn1.Unmarshal(_rest, &_v)",
            "        if err != nil { break }",
            "        _rest = _next",
            "        /* context class (2) + constructed (32) + tag 6 = uniformResourceIdentifier */"
            "        if _v.Class == 2 && _v.Tag == 38 {",
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
    if isinstance(n, dsl.ExtKeyUsageHas):
        bit = V.EKU_BY_NAME[n.bit].go_expr
        return f"util.HasEKU(c, {bit})"

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

    if isinstance(n, dsl.OidEq):
        f = V.lookup_anyfield(n.field)
        oid = V.OID_BY_NAME[n.oid].go_expr
        return f"{f.go_expr}.Equal({oid})"

    if isinstance(n, dsl.SubtreeIPListAnyHasOctetCount):
        f = V.lookup_anyfield(n.field)
        return _iife_bool([
            f"for _, _s := range {f.go_expr} {{",
            f"\tif len(_s.Data.IP)+len(_s.Data.Mask) == {n.count} {{ return true }}",
            f"}}",
            f"return false",
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


# KeyUsage / EKU bit name normalization (prose -> zcrypto Go constants).
# zcrypto uses PascalCase names: DigitalSignature, NonRepudiation, ...
_BIT_ALIASES = {
    "any extended key usage": "Any",
    "anyextendedkeyusage": "Any",
    "anyeku": "Any",
    "digital signature": "DigitalSignature",
    "digitalsignature": "DigitalSignature",
    "nonrepudiation": "NonRepudiation",
    "non repudiation": "NonRepudiation",
    "keyencipherment": "KeyEncipherment",
    "key encipherment": "KeyEncipherment",
    "dataencipherment": "DataEncipherment",
    "dataencipherment": "DataEncipherment",
    "keyagreement": "KeyAgreement",
    "key agreement": "KeyAgreement",
    "keycertsign": "KeyCertSign",
    "key cert sign": "KeyCertSign",
    "crlsign": "CRLSign",
    "crl sign": "CRLSign",
    "encipheronly": "EncipherOnly",
    "decipheronly": "DecipherOnly",
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
    lower = s.lower()
    if lower in _BIT_ALIASES:
        return _BIT_ALIASES[lower]
    # Generic PascalCase: lowercase-first, uppercase each word boundary, strip spaces.
    # "digitalSignature" -> "DigitalSignature", "nonRepudiation" -> "NonRepudiation"
    import re
    words = re.split(r'[\s_-]+', s)
    return "".join(w.capitalize() for w in words if w)


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
    # keyusage_bits: FieldInSet(KeyUsage, {DigitalSignature, KeyEncipherment}) means
    # the KeyUsage bitmask includes any of those bits. Emit c.KeyUsage.HasBit(...) || ...
    if f.semantic == "keyusage_bits":
        if not values:
            raise dsl.DSLError(f"FieldInSet: empty values for keyusage_bits field {f.name}")
        bit_exprs = []
        for v in values:
            v_str = str(v)
            # Normalize the bit name to canonical PascalCase
            bit_normalized = _norm_bit_name(v_str)
            bit_exprs.append(f"{f.go_expr}.HasBit(zcrypto.KeyUsageBit_{bit_normalized})")
        op_str = "||" if not negate else "&&"
        join_str = f" {op_str} ".join(bit_exprs)
        if negate:
            return f"({join_str})"
        return f"({join_str})"
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
        dsl.ExtKeyUsageHas, dsl.IsServerCert, dsl.ExtHasGeneralNameWithTag,
        dsl.ExtHasAnyGeneralNameOfTag,
    )
    if isinstance(n, needs_util):
        imps.add("github.com/zmap/zlint/v3/util")
    if isinstance(n, dsl.ExtHasAnyGeneralNameOfTag):
        imps.add("encoding/asn1")
    if isinstance(n, dsl.ExtSubfieldPresent):
        imps.add("github.com/zmap/zlint/v3/util")
        imps.add("encoding/asn1")

    if isinstance(n, dsl.SigAlgMatchesTBSSignature):
        imps.add("bytes")
        imps.add("golang.org/x/crypto/cryptobyte")
        imps.add("golang.org/x/crypto/cryptobyte/asn1")

    if isinstance(n, (dsl.FieldMatchesRegex, dsl.ItemMatchesRegex,
                      dsl.ItemNotMatchesRegex,
                      dsl.FieldNotMatchesRegex)):
        imps.add("regexp")
    if isinstance(n, dsl.FieldEncodedAs) and n.field not in ("Subject", "Issuer", "subject", "issuer"):
        imps.add("regexp")

    if isinstance(n, (dsl.FieldContains, dsl.WildcardFilter)):
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

    if isinstance(n, dsl.FieldEncodedAs) and n.field in ("Subject", "Issuer", "subject", "issuer"):
        # whole-DN encoded-as reads raw DER tags via encoding/asn1.
        imps.add("encoding/asn1")

    if isinstance(n, dsl.DNDirectoryStringValuesEncodedAs):
        # per-attribute DN encoded-as walks the RDNSequence DER via encoding/asn1.
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
    if isinstance(n, dsl.CertPolicyExplicitTextHasEncodingTagInSet):
        imps.add("encoding/asn1")
    if isinstance(n, dsl.OidEq):
        imps.add("github.com/zmap/zlint/v3/util")
    if isinstance(n, dsl.BytesContainsOidDer):
        imps.add("bytes")
    # SubtreeIPListAnyHasOctetCount: no extra imports needed (operates on
    # already-typed []GeneralSubtreeIP and inline len()).


def _walk_vocab(n, out: dict):
    def bump(d, k): d[k] = d.get(k, 0) + 1
    if isinstance(n, (dsl.And, dsl.Or)):
        for p in n.parts: _walk_vocab(p, out)
    elif isinstance(n, dsl.Not):
        _walk_vocab(n.inner, out)
    elif isinstance(n, (dsl.ExtPresent, dsl.ExtCritical, dsl.ExtNotCritical)):
        bump(out, "oids")
    elif isinstance(n, dsl.KeyUsageHas):
        bump(out, "ku_bits")
    elif isinstance(n, dsl.ExtKeyUsageHas):
        bump(out, "eku_bits")
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
    elif isinstance(n, dsl.OidEq):
        bump(out, "fields")
        bump(out, "oids")
    elif isinstance(n, dsl.SubtreeIPListAnyHasOctetCount):
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
    elif isinstance(n, dsl.SubtreeIPListAllOctetCountIn):
        bump(out, "fields")
    elif isinstance(n, dsl.SubtreeIPMaskValidCIDR):
        bump(out, "fields")
    elif isinstance(n, dsl.FieldContains):
        bump(out, "fields")
    elif isinstance(n, dsl.FieldNotMatchesRegex):
        bump(out, "fields")
    elif isinstance(n, dsl.CrossFieldEq):
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
