"""
专门的zlint代码生成器

为特定的规则模式生成完整的、经验证的zlint代码。
不使用通用的参数化方法，而是为每个规则模式提供专门的实现。

生成的代码符合zlint v3标准格式：
- 使用 lint.RegisterCertificateLint
- 使用 LintMetadata 结构体
- 使用 New...() 构造函数
- 正确的 import 路径 (github.com/zmap/zcrypto/x509)
"""
from typing import Dict, Any, Optional
from app.core.logging_config import app_logger
from app.services.certificate.rule_pattern_detector import ZlintRulePattern


class SpecializedZlintCodeGenerator:
    """为特定规则模式生成zlint代码

    核心设计：不是通用参数化生成，而是规则模式识别和专门生成。

    原因：
    1. 不同的规则有不同的执行模式
    2. 通用参数化生成无法处理复杂规则
    3. 专门生成器可以生成完整的、经验证的代码
    4. 易于维护和扩展
    """

    def generate(self, ir: Dict[str, Any], pattern: ZlintRulePattern) -> Optional[str]:
        """生成对应规则模式的完整Go代码

        Args:
            ir: 规则的中间表示
            pattern: 检测到的规则模式

        Returns:
            完整的Go代码，或None（如果无法生成）
        """

        generators = {
            ZlintRulePattern.DN_ATTRIBUTE_TYPE_CHECK: self._gen_dn_attribute_type_check,
            ZlintRulePattern.DNS_LABEL_LENGTH_CHECK: self._gen_dns_label_length_check,
            ZlintRulePattern.ACE_FORMAT_CHECK: self._gen_ace_format_check,
            ZlintRulePattern.DN_FIELD_ASCII_CHECK: self._gen_dn_field_ascii_check,
            ZlintRulePattern.EXTENSION_PRESENCE: self._gen_extension_presence,
            ZlintRulePattern.DNSNAME_ASCII_CHECK: self._gen_dnsname_ascii_check,
            ZlintRulePattern.LDH_LABEL_CHECK: self._gen_ldh_label_check,
        }

        generator = generators.get(pattern)
        if not generator:
            app_logger.warning(f"No specialized generator for pattern: {pattern}")
            return None

        try:
            code = generator(ir)
            if code:
                app_logger.debug(f"Successfully generated code for pattern: {pattern}")
            return code
        except Exception as e:
            app_logger.error(f"Error generating code for pattern {pattern}: {e}")
            return None

    # ==================== 规则模式生成函数 ====================

    def _gen_dn_attribute_type_check(self, ir: Dict[str, Any]) -> Optional[str]:
        """生成DN属性ASN.1类型检查

        示例规则: Subject DN中的特定属性（CN, O, OU等）必须是UTF8String或PrintableString

        对应用户示例代码: subjectDNEncoding
        """

        # 从IR提取信息
        raw_lint_name = ir.get('lint_name') or 'e_subject_dn_utf8_or_printable'
        lint_name = self._normalize_lint_name(raw_lint_name)
        description = ir.get('description') or 'Standard naming attributes (CN, O, OU) must be UTF8String or PrintableString'
        raw_citation = ir.get('citation') or 'RFC 5280: 7.1'
        citation = self._format_citation(raw_citation, 'RFC5280')

        # 支持的OID默认值（CN, O, OU）
        oids = ir.get('check_oids') or ['2.5.4.3', '2.5.4.10', '2.5.4.11']
        oid_cases = ', '.join(f'"{oid}"' for oid in oids)

        struct_name = self._to_struct_name(lint_name)
        package = ir.get('package') or 'rfc'
        desc_escaped = self._escape_description(description)

        return f'''package {package}

/*
 * ZLint Copyright 2024 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type {struct_name} struct{{}}

func init() {{
	lint.RegisterCertificateLint(&lint.CertificateLint{{
		LintMetadata: lint.LintMetadata{{
			Name:          "{lint_name}",
			Description:   "{desc_escaped}",
			Citation:      "{citation}",
			Source:        lint.RFC5280,
			EffectiveDate: util.RFC5280Date,
		}},
		Lint: New{struct_name},
	}})
}}

func New{struct_name}() lint.CertificateLintInterface {{
	return &{struct_name}{{}}
}}

func (l *{struct_name}) CheckApplies(c *x509.Certificate) bool {{
	return true // Subject DN always present in certificates
}}

func (l *{struct_name}) Execute(c *x509.Certificate) *lint.LintResult {{
	// Check that specific DN attributes are encoded as UTF8String or PrintableString
	// If properly encoded, zcrypto parses them as Go strings
	// Other types (BMPString, UniversalString, etc.) will fail type assertion
	for _, atv := range c.Subject.Names {{
		switch atv.Type.String() {{
		case {oid_cases}: // CN, O, OU
			derType := atv.Value.(interface{{}})
			_, ok := derType.(string)
			if !ok {{
				return &lint.LintResult{{
					Status:  lint.Error,
					Details: "DN attribute " + atv.Type.String() + " is not UTF8String or PrintableString",
				}}
			}}
		}}
	}}
	return &lint.LintResult{{Status: lint.Pass}}
}}
'''

    def _gen_dns_label_length_check(self, ir: Dict[str, Any]) -> Optional[str]:
        """生成DNS标签长度检查

        示例规则: DNS标签最多63个八进制字符（包括IDN的Unicode和Punycode形式）

        对应用户示例代码: idnLabelLength
        """

        raw_lint_name = ir.get('lint_name') or 'e_idn_label_max_length'
        lint_name = self._normalize_lint_name(raw_lint_name)
        description = ir.get('description') or 'Each IDN label must be at most 63 characters (ACE/Punycode)'
        raw_citation = ir.get('citation') or 'RFC 5280: 7.2'
        citation = self._format_citation(raw_citation, 'RFC5280')
        max_length = ir.get('max_label_length') or 63  # 默认63字节
        struct_name = self._to_struct_name(lint_name)
        package = ir.get('package') or 'rfc'
        desc_escaped = self._escape_description(description)

        return f'''package {package}

/*
 * ZLint Copyright 2024 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

import (
	"strings"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type {struct_name} struct{{}}

func init() {{
	lint.RegisterCertificateLint(&lint.CertificateLint{{
		LintMetadata: lint.LintMetadata{{
			Name:          "{lint_name}",
			Description:   "{desc_escaped}",
			Citation:      "{citation}",
			Source:        lint.RFC5280,
			EffectiveDate: util.RFC5280Date,
		}},
		Lint: New{struct_name},
	}})
}}

func New{struct_name}() lint.CertificateLintInterface {{
	return &{struct_name}{{}}
}}

func (l *{struct_name}) CheckApplies(c *x509.Certificate) bool {{
	// Only applies if certificate has DNS names in SubjectAltName
	return len(c.DNSNames) > 0
}}

func (l *{struct_name}) Execute(c *x509.Certificate) *lint.LintResult {{
	for _, dns := range c.DNSNames {{
		// Split the domain name into labels by "."
		labels := strings.Split(dns, ".")
		for _, label := range labels {{
			// Each label must be at most {max_length} octets
			// This applies to both ACE (Punycode) and Unicode forms
			if len(label) > {max_length} {{
				return &lint.LintResult{{
					Status:  lint.Error,
					Details: "DNS label exceeds {max_length} octets: " + label,
				}}
			}}
		}}
	}}
	return &lint.LintResult{{Status: lint.Pass}}
}}
'''

    def _gen_ace_format_check(self, ir: Dict[str, Any]) -> Optional[str]:
        """生成ACE/Punycode格式检查

        示例规则: 国际化域名的ACE编码形式必须是有效的Punycode（仅ASCII）

        对应用户示例代码: allowUnassignedCheck
        """

        raw_lint_name = ir.get('lint_name') or 'e_idn_allow_unassigned_flag'
        lint_name = self._normalize_lint_name(raw_lint_name)
        description = ir.get('description') or 'Ensure AllowUnassigned flag is not set for IDN ACE labels'
        raw_citation = ir.get('citation') or 'RFC 5280: 7.2'
        citation = self._format_citation(raw_citation, 'RFC5280')
        ace_prefix = ir.get('ace_prefix') or 'xn--'  # ACE标签前缀
        struct_name = self._to_struct_name(lint_name)
        package = ir.get('package') or 'rfc'
        desc_escaped = self._escape_description(description)

        return f'''package {package}

/*
 * ZLint Copyright 2024 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

import (
	"strings"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type {struct_name} struct{{}}

func init() {{
	lint.RegisterCertificateLint(&lint.CertificateLint{{
		LintMetadata: lint.LintMetadata{{
			Name:          "{lint_name}",
			Description:   "{desc_escaped}",
			Citation:      "{citation}",
			Source:        lint.RFC5280,
			EffectiveDate: util.RFC5280Date,
		}},
		Lint: New{struct_name},
	}})
}}

func New{struct_name}() lint.CertificateLintInterface {{
	return &{struct_name}{{}}
}}

func (l *{struct_name}) CheckApplies(c *x509.Certificate) bool {{
	return len(c.DNSNames) > 0
}}

func (l *{struct_name}) Execute(c *x509.Certificate) *lint.LintResult {{
	// Verify ACE-encoded (Punycode) labels are valid
	for _, dns := range c.DNSNames {{
		labels := strings.Split(dns, ".")
		for _, label := range labels {{
			// Check if this is an ACE-encoded label (starts with xn--)
			if strings.HasPrefix(strings.ToLower(label), "{ace_prefix}") {{
				// ACE labels must contain only ASCII characters (0-127)
				// Non-ASCII indicates invalid encoding or AllowUnassigned was used
				for _, r := range label {{
					if r > 127 {{
						return &lint.LintResult{{
							Status:  lint.Error,
							Details: "ACE label contains non-ASCII character: " + label,
						}}
					}}
				}}
			}}
		}}
	}}
	return &lint.LintResult{{Status: lint.Pass}}
}}
'''

    def _gen_dn_field_ascii_check(self, ir: Dict[str, Any]) -> Optional[str]:
        """生成DN字段ASCII检查

        示例规则: DN中的domainComponent字段必须能通过IDNA ToASCII编码

        对应用户示例代码: dnIDNToASCII
        """

        raw_lint_name = ir.get('lint_name') or 'e_dn_idn_toascii'
        lint_name = self._normalize_lint_name(raw_lint_name)
        description = ir.get('description') or 'DN domainComponent labels must be ToASCII encoded'
        raw_citation = ir.get('citation') or 'RFC 5280: 7.3'
        citation = self._format_citation(raw_citation, 'RFC5280')
        oid = ir.get('oid') or '0.9.2342.19200300.100.1.25'  # domainComponent OID
        struct_name = self._to_struct_name(lint_name)
        package = ir.get('package') or 'rfc'
        desc_escaped = self._escape_description(description)

        return f'''package {package}

/*
 * ZLint Copyright 2024 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
	"golang.org/x/net/idna"
)

type {struct_name} struct{{}}

func init() {{
	lint.RegisterCertificateLint(&lint.CertificateLint{{
		LintMetadata: lint.LintMetadata{{
			Name:          "{lint_name}",
			Description:   "{desc_escaped}",
			Citation:      "{citation}",
			Source:        lint.RFC5280,
			EffectiveDate: util.RFC5280Date,
		}},
		Lint: New{struct_name},
	}})
}}

func New{struct_name}() lint.CertificateLintInterface {{
	return &{struct_name}{{}}
}}

func (l *{struct_name}) CheckApplies(c *x509.Certificate) bool {{
	return len(c.Subject.Names) > 0
}}

func (l *{struct_name}) Execute(c *x509.Certificate) *lint.LintResult {{
	// Verify domainComponent attributes can be ASCII-encoded via IDNA ToASCII
	for _, atv := range c.Subject.Names {{
		// domainComponent OID: {oid}
		if atv.Type.String() == "{oid}" {{
			str, ok := atv.Value.(string)
			if !ok {{
				continue
			}}

			// Use IDNA2008 Lookup profile for certificate validation
			_, err := idna.Lookup.ToASCII(str)
			if err != nil {{
				return &lint.LintResult{{
					Status:  lint.Error,
					Details: "domainComponent value is not acceptable as RFC 3490 ToASCII output",
				}}
			}}
		}}
	}}
	return &lint.LintResult{{Status: lint.Pass}}
}}
'''

    def _gen_extension_presence(self, ir: Dict[str, Any]) -> Optional[str]:
        """生成扩展必须存在检查

        规则: 特定扩展必须在证书中存在
        """

        raw_lint_name = ir.get('lint_name') or 'e_extension_required'
        lint_name = self._normalize_lint_name(raw_lint_name)
        description = ir.get('description') or 'Required extension must be present'
        raw_citation = ir.get('citation') or 'RFC 5280'
        citation = self._format_citation(raw_citation, 'RFC5280')
        oid_const = ir.get('extension_oid_const')
        struct_name = self._to_struct_name(lint_name)
        package = ir.get('package') or 'rfc'
        desc_escaped = self._escape_description(description)

        if not oid_const:
            app_logger.warning(f"Cannot generate extension presence check: missing extension_oid_const")
            return None

        return f'''package {package}

/*
 * ZLint Copyright 2024 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type {struct_name} struct{{}}

func init() {{
	lint.RegisterCertificateLint(&lint.CertificateLint{{
		LintMetadata: lint.LintMetadata{{
			Name:          "{lint_name}",
			Description:   "{desc_escaped}",
			Citation:      "{citation}",
			Source:        lint.RFC5280,
			EffectiveDate: util.RFC5280Date,
		}},
		Lint: New{struct_name},
	}})
}}

func New{struct_name}() lint.CertificateLintInterface {{
	return &{struct_name}{{}}
}}

func (l *{struct_name}) CheckApplies(c *x509.Certificate) bool {{
	return true
}}

func (l *{struct_name}) Execute(c *x509.Certificate) *lint.LintResult {{
	if !util.IsExtInCert(c, util.{oid_const}) {{
		return &lint.LintResult{{
			Status:  lint.Error,
			Details: "Required extension is missing",
		}}
	}}
	return &lint.LintResult{{Status: lint.Pass}}
}}
'''

    def _gen_dnsname_ascii_check(self, ir: Dict[str, Any]) -> Optional[str]:
        """生成dNSName ASCII-only检查

        规则: dNSName值必须只包含ASCII字符 (0-127)

        这验证了国际化域名在存储到证书之前已正确执行ToASCII转换。
        RFC 5280 §7.2: dNSName是IA5String编码，限制为ASCII字符。
        如果存在非ASCII字符，表示ToASCII转换未正确执行。
        """

        raw_lint_name = ir.get('lint_name') or 'e_dnsname_must_be_ascii'
        lint_name = self._normalize_lint_name(raw_lint_name)
        description = ir.get('description') or 'dNSName values must contain only ASCII characters (RFC 5280 Section 7.2)'
        raw_citation = ir.get('citation') or 'RFC 5280: 7.2'
        citation = self._format_citation(raw_citation, 'RFC5280')
        struct_name = self._to_struct_name(lint_name)
        package = ir.get('package') or 'rfc'
        desc_escaped = self._escape_description(description)

        return f'''package {package}

/*
 * ZLint Copyright 2024 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

import (
	"fmt"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type {struct_name} struct{{}}

func init() {{
	lint.RegisterCertificateLint(&lint.CertificateLint{{
		LintMetadata: lint.LintMetadata{{
			Name:          "{lint_name}",
			Description:   "{desc_escaped}",
			Citation:      "{citation}",
			Source:        lint.RFC5280,
			EffectiveDate: util.RFC5280Date,
		}},
		Lint: New{struct_name},
	}})
}}

func New{struct_name}() lint.CertificateLintInterface {{
	return &{struct_name}{{}}
}}

func (l *{struct_name}) CheckApplies(c *x509.Certificate) bool {{
	// Only applies if certificate has DNS names in SubjectAltName
	return len(c.DNSNames) > 0
}}

func (l *{struct_name}) Execute(c *x509.Certificate) *lint.LintResult {{
	// RFC 5280 Section 7.2: dNSName is encoded as IA5String, which is
	// limited to ASCII characters (0-127). Internationalized domain names
	// MUST be converted to ASCII Compatible Encoding (ACE) format before
	// storage. If non-ASCII characters are present, the conversion was
	// not performed correctly.
	for _, dns := range c.DNSNames {{
		for i, r := range dns {{
			if r > 127 {{
				return &lint.LintResult{{
					Status:  lint.Error,
					Details: fmt.Sprintf("dNSName contains non-ASCII character at position %d: %q", i, dns),
				}}
			}}
		}}
	}}
	return &lint.LintResult{{Status: lint.Pass}}
}}
'''

    def _gen_ldh_label_check(self, ir: Dict[str, Any]) -> Optional[str]:
        """生成LDH标签检查（UseSTD3ASCIIRules）

        规则: DNS标签必须符合LDH规则：
        1. 只能包含字母(a-z, A-Z)、数字(0-9)和连字符(-)
        2. 不能以连字符开头或结尾

        这验证了UseSTD3ASCIIRules flag已被正确设置。
        RFC 5280 §7.2 要求: "in step 3, set the flag called UseSTD3ASCIIRules"
        UseSTD3ASCIIRules的效果是确定性的、时间不变的，可通过modus tollens逆推验证。
        """

        raw_lint_name = ir.get('lint_name') or 'e_dnsname_label_must_be_ldh'
        lint_name = self._normalize_lint_name(raw_lint_name)
        description = ir.get('description') or 'DNS labels must contain only letters, digits, and hyphens (UseSTD3ASCIIRules)'
        raw_citation = ir.get('citation') or 'RFC 5280: 7.2'
        citation = self._format_citation(raw_citation, 'RFC5280')
        struct_name = self._to_struct_name(lint_name)
        package = ir.get('package') or 'rfc'
        desc_escaped = self._escape_description(description)

        return f'''package {package}

/*
 * ZLint Copyright 2024 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type {struct_name} struct{{
	nonLDHRegex *regexp.Regexp
}}

func init() {{
	lint.RegisterCertificateLint(&lint.CertificateLint{{
		LintMetadata: lint.LintMetadata{{
			Name:          "{lint_name}",
			Description:   "{desc_escaped}",
			Citation:      "{citation}",
			Source:        lint.RFC5280,
			EffectiveDate: util.RFC5280Date,
		}},
		Lint: New{struct_name},
	}})
}}

func New{struct_name}() lint.CertificateLintInterface {{
	return &{struct_name}{{
		nonLDHRegex: regexp.MustCompile(`[^a-zA-Z0-9\\-]`),
	}}
}}

func (l *{struct_name}) CheckApplies(c *x509.Certificate) bool {{
	return len(c.DNSNames) > 0
}}

func (l *{struct_name}) Execute(c *x509.Certificate) *lint.LintResult {{
	// RFC 5280 Section 7.2 requires UseSTD3ASCIIRules to be set.
	// This means DNS labels must:
	// 1. Contain only LDH characters (letters, digits, hyphens)
	// 2. Not begin or end with a hyphen
	for _, dns := range c.DNSNames {{
		labels := strings.Split(dns, ".")
		for i, label := range labels {{
			// Skip wildcard in leftmost position
			if i == 0 && label == "*" {{
				continue
			}}
			// Skip empty labels (caught by separate lint)
			if label == "" {{
				continue
			}}
			// Check for non-LDH characters
			if l.nonLDHRegex.MatchString(label) {{
				return &lint.LintResult{{
					Status:  lint.Error,
					Details: fmt.Sprintf("DNS label %q in %q contains non-LDH character", label, dns),
				}}
			}}
			// Check for leading hyphen
			if strings.HasPrefix(label, "-") {{
				return &lint.LintResult{{
					Status:  lint.Error,
					Details: fmt.Sprintf("DNS label %q in %q starts with a hyphen", label, dns),
				}}
			}}
			// Check for trailing hyphen
			if strings.HasSuffix(label, "-") {{
				return &lint.LintResult{{
					Status:  lint.Error,
					Details: fmt.Sprintf("DNS label %q in %q ends with a hyphen", label, dns),
				}}
			}}
		}}
	}}
	return &lint.LintResult{{Status: lint.Pass}}
}}
'''

    @staticmethod
    def _to_struct_name(lint_name: str) -> str:
        """转换lint名称为Go结构体名称

        Examples:
            e_subject_dn_utf8_or_printable -> SubjectDnUtf8OrPrintable
            e_idn_label_max_length -> IdnLabelMaxLength
            e_extension_required -> ExtensionRequired
            subject.domainComponent_must_perform -> DomaincomponentMustPerform
            extensions.subjectAltName.dNSName_must_be_ascii -> DnsnameMustBeAscii
        """
        # 移除前缀 e_ 或 w_（都是小写）
        if lint_name.startswith('e_'):
            name = lint_name[2:]
        elif lint_name.startswith('w_'):
            name = lint_name[2:]
        else:
            name = lint_name

        # 将点号替换为下划线（Go标识符不能包含点号）
        name = name.replace('.', '_')

        # Remove redundant path segments for shorter names
        skip_segments = {'extensions', 'subjectaltname', 'subject', 'issuer', 'tbscertificate'}
        parts = [p for p in name.split('_') if p.lower() not in skip_segments and p]

        return ''.join(p.capitalize() for p in parts)

    @staticmethod
    def _escape_description(desc: str) -> str:
        """转义描述字符串用于Go字符串字面量"""
        # 替换引号和换行符
        desc = desc.replace('"', '\\"').replace('\n', ' ')

        # 移除或替换非ASCII字符
        cleaned = ''
        for ch in desc:
            if 32 <= ord(ch) <= 126:
                cleaned += ch
            elif ch == '\t':
                cleaned += ' '
            # 忽略其他非ASCII字符

        # 限制长度
        if len(cleaned) > 200:
            cleaned = cleaned[:197] + '...'

        return cleaned

    def _normalize_lint_name(self, ir_lint_name: str) -> str:
        """
        Convert IR path-style lint_name to zlint convention.

        IR style: extensions.subjectAltName.dNSName_must_perform_storage
        zlint style: e_dns_name_must_be_ascii

        Args:
            ir_lint_name: The lint name from the IR

        Returns:
            Normalized lint name following zlint conventions
        """
        name = ir_lint_name.lower()

        # Remove verbose path prefixes
        for prefix in ['extensions.subjectaltname.', 'extensions.', 'subject.', 'issuer.']:
            if name.startswith(prefix):
                name = name[len(prefix):]
                break

        # Simplify field names
        name = name.replace('dnsname', 'dns_name')
        name = name.replace('domaincomponent', 'dc')

        # Add e_ prefix if missing
        if not name.startswith('e_') and not name.startswith('w_'):
            name = 'e_' + name

        return name

    def _format_citation(self, citation: str, source: str = 'RFC5280') -> str:
        """
        Format citation to match zlint convention.

        Input: "7.2"
        Output: "RFC 5280 Section 7.2"

        Args:
            citation: The raw citation string (e.g., "7.2", "RFC 5280: 7.2")
            source: The source identifier (e.g., "RFC5280")

        Returns:
            Formatted citation string
        """
        if not citation:
            return source

        # If already properly formatted, return as-is
        if 'Section' in citation:
            return citation

        # Extract section number from various formats
        section = citation.split(':')[-1].strip() if ':' in citation else citation

        # Map source identifiers to human-readable format
        rfc_map = {
            'RFC5280': 'RFC 5280',
            'RFC2459': 'RFC 2459',
            'RFC3279': 'RFC 3279',
            'RFC3280': 'RFC 3280'
        }
        rfc_name = rfc_map.get(source, source)

        return f"{rfc_name} Section {section}"
