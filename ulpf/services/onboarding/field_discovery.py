"""
Field Discovery & OCSF Mapping Advisor
Performs heuristic type inference and generates candidate OCSF 1.1.0 field mappings from Drain3 templates.
"""

import re

from ulpf.packages.schemas.models import ParserRule, TemplateVariable


class FieldDiscoveryEngine:
    """
    Analyzes variable placeholders from Drain3 mined templates, infers types,
    and proposes intelligent OCSF mappings.
    """

    IP_REGEX = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    ISO_DATE_REGEX = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")
    PROTO_NAMES = {"TCP", "UDP", "ICMP", "GRE", "ESP", "AH", "HTTP", "HTTPS", "DNS", "SSH"}
    ACTIONS = {"ALLOW", "DENY", "DROP", "BLOCK", "REJECT", "ACCEPT", "PERMIT", "PASS"}

    def analyze_template_and_samples(
        self,
        template_str: str,
        sample_logs: list[str]
    ) -> tuple[list[TemplateVariable], str, list[ParserRule]]:
        """
        1. Identifies variable placeholders in template.
        2. Converts template into regex with named capture groups.
        3. Extracts sample values for each placeholder.
        4. Infers data types and suggests OCSF target fields.
        5. Generates ParserRule definitions.
        """
        regex_pattern, var_names, var_placeholders = self._template_to_regex(template_str, sample_logs)

        compiled_re = None
        try:
            compiled_re = re.compile(regex_pattern, re.IGNORECASE)
        except re.error:
            pass

        # Collect sample values for each variable
        samples_by_var: dict[str, list[str]] = {v: [] for v in var_names}
        if compiled_re:
            for s in sample_logs:
                m = compiled_re.search(s.strip())
                if m:
                    for v in var_names:
                        val = m.groupdict().get(v)
                        if val and val not in samples_by_var[v]:
                            samples_by_var[v].append(val)

        # Infer types and OCSF targets
        variables: list[TemplateVariable] = []
        rules: list[ParserRule] = []

        ip_count = 0
        port_count = 0

        for idx, v_name in enumerate(var_names):
            placeholder = var_placeholders[idx]
            vals = samples_by_var.get(v_name, [])
            inferred_type, ocsf_field, confidence, transform = self._infer_field_mapping(
                v_name, placeholder, vals, ip_count, port_count
            )

            if inferred_type == "ipv4":
                ip_count += 1
            elif inferred_type == "port":
                port_count += 1

            variables.append(TemplateVariable(
                var_index=idx,
                placeholder=placeholder,
                sample_values=vals[:5] if vals else [placeholder],
                inferred_type=inferred_type,
                suggested_ocsf_field=ocsf_field,
                confidence=confidence
            ))

            rules.append(ParserRule(
                field_name=v_name,
                target_ocsf_field=ocsf_field,
                transform=transform
            ))

        return variables, regex_pattern, rules

    def _template_to_regex(self, template_str: str, sample_logs: list[str] | None = None) -> tuple[str, list[str], list[str]]:
        """
        Converts Drain3 template into regex pattern with named groups (?P<var_0>...)
        Generalizes key=value tokens into value capture groups.
        """
        # Step 1: Pre-process template: if there are KEY=VALUE tokens that aren't masked, generalize value
        def _generalize_kv(m):
            key, val = m.group(1), m.group(2)
            if val.startswith("<") and val.endswith(">"):
                return m.group(0)
            return f"{key}=<{key}>"

        working_tmpl = re.sub(r'([A-Za-z0-9_]+)=([^\s,;|]+)', _generalize_kv, template_str)

        token_pattern = re.compile(r"<([^>]+)>")
        parts = []
        var_names = []
        var_placeholders = []
        last_end = 0
        var_idx = 0

        for m in token_pattern.finditer(working_tmpl):
            literal_prefix = working_tmpl[last_end:m.start()]
            parts.append(re.escape(literal_prefix))

            token_type = m.group(1)
            placeholder = f"<{token_type}>"
            var_name = f"var_{var_idx}"

            # If previous literal ended with key= or key:
            key_match = re.search(r'([a-zA-Z0-9_]+)[=:]\s*$', literal_prefix)
            if key_match:
                key_label = key_match.group(1).lower()
                var_name = f"{key_label}_{var_idx}"
            elif token_type.lower() in ["ip", "num", "timestamp", "str", "uuid", "rule", "proto", "action", "bytes", "dev"]:
                var_name = f"{token_type.lower()}_{var_idx}"

            var_names.append(var_name)
            var_placeholders.append(placeholder)

            if token_type.upper() == "IP" or "ip" in var_name:
                group_regex = rf"(?P<{var_name}>(?:[0-9]{{1,3}}\.){{3}}[0-9]{{1,3}})"
            elif token_type.upper() == "NUM" or "port" in var_name or "bytes" in var_name:
                group_regex = rf"(?P<{var_name}>\d+)"
            elif token_type.upper() == "TIMESTAMP" or "time" in var_name or "date" in var_name:
                group_regex = rf"(?P<{var_name}>\d{{4}}-\d{{2}}-\d{{2}}[T ]\d{{2}}:\d{{2}}:\d{{2}}(?:\.\d+)?(?:Z|[+-]\d{{2}}:?\d{{2}})?)"
            elif token_type.upper() == "STR" or "reason" in var_name or "msg" in var_name:
                group_regex = rf'(?P<{var_name}>"[^"]*"|\'[^\']*\'|[^\s,;|]+)'
            elif token_type.upper() == "UUID":
                group_regex = rf"(?P<{var_name}>[0-9a-fA-F-]{{36}})"
            else:
                group_regex = rf'(?P<{var_name}>"[^"]*"|\'[^\']*\'|[^\s,;|]+)'

            parts.append(group_regex)
            last_end = m.end()
            var_idx += 1

        parts.append(re.escape(working_tmpl[last_end:]))
        regex_pattern = "".join(parts)
        return regex_pattern, var_names, var_placeholders

    def _infer_field_mapping(
        self,
        var_name: str,
        placeholder: str,
        samples: list[str],
        ip_count: int,
        port_count: int
    ) -> tuple[str, str, float, str | None]:
        """
        Determines type, suggested OCSF field, confidence score, and transform function.
        """
        name_lower = var_name.lower()
        first_sample = samples[0].strip().strip('"').strip("'") if samples else ""

        # Check IP Address
        if placeholder == "<IP>" or "ip" in name_lower or "src" in name_lower or "dst" in name_lower:
            if self.IP_REGEX.match(first_sample) or placeholder == "<IP>":
                if "src" in name_lower or ip_count == 0:
                    return "ipv4", "src_ip", 0.95, None
                else:
                    return "ipv4", "dst_ip", 0.95, None

        # Check Port
        if "port" in name_lower or "spt" in name_lower or "dpt" in name_lower or (placeholder == "<NUM>" and first_sample.isdigit() and 1 <= int(first_sample) <= 65535 and ("src" in name_lower or "dst" in name_lower)):
            if "src" in name_lower or port_count == 0:
                return "port", "src_port", 0.92, "to_int"
            else:
                return "port", "dst_port", 0.92, "to_int"

        # Check Protocol
        if "proto" in name_lower or first_sample.upper() in self.PROTO_NAMES:
            return "protocol", "protocol", 0.95, "to_upper"

        # Check Action / Disposition
        if "action" in name_lower or "act" in name_lower or first_sample.upper() in self.ACTIONS:
            return "action", "action", 0.95, "to_lower"

        # Check Timestamp
        if placeholder == "<TIMESTAMP>" or "time" in name_lower or "date" in name_lower or self.ISO_DATE_REGEX.match(first_sample):
            return "timestamp", "timestamp", 0.90, None

        # Check Bytes
        if "byte" in name_lower or "size" in name_lower:
            return "integer", "bytes", 0.90, "to_int"

        # Check Rule / Policy
        if "rule" in name_lower or "policy" in name_lower:
            return "string", "rule_name", 0.88, None

        # Check User
        if "user" in name_lower or "usr" in name_lower:
            return "string", "user_name", 0.85, None

        # Check Reason / Message
        if "reason" in name_lower or "msg" in name_lower:
            return "string", "message", 0.80, None

        # Fallback based on sample value type
        if first_sample.isdigit():
            return "integer", f"unmapped_{var_name}", 0.70, "to_int"

        return "string", f"unmapped_{var_name}", 0.65, None
