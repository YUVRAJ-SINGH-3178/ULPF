"""
Drain3 Dynamic Template Parser
Generated when an unknown log format is onboarded through Drain3 template mining and human approval.
"""

import re
from typing import Any

from ulpf.packages.schemas.models import (
    FormatType,
    ParserRule,
    ParserStatus,
    SourceMetadata,
)
from ulpf.services.parser_engine.base import BaseParser


class Drain3DynamicParser(BaseParser):
    """
    Executes regex/template extraction based on approved Drain3 discovered patterns and field mappings.
    """

    def __init__(
        self,
        parser_id: str,
        vendor: str,
        product: str,
        version: str,
        template_str: str,
        compiled_regex: str,
        rules: list[ParserRule],
        target_class: str = "Network Activity",
        target_class_uid: int = 4001,
        status: ParserStatus = ParserStatus.ACTIVE,
    ):
        super().__init__(
            parser_id=parser_id,
            vendor=vendor,
            product=product,
            format_type=FormatType.PROPRIETARY,
            version=version,
            target_class=target_class,
            target_class_uid=target_class_uid,
            status=status,
        )
        self.template_str = template_str
        self.compiled_regex = compiled_regex
        self.rules = rules
        try:
            self._pattern = re.compile(compiled_regex)
        except re.error:
            self._pattern = None

    def matches(
        self, raw_payload: str, source_meta: SourceMetadata | None = None
    ) -> bool:
        if not self._pattern:
            return False
        return bool(self._pattern.search(raw_payload.strip()))

    def parse_fields(
        self, raw_payload: str, source_meta: SourceMetadata | None = None
    ) -> dict[str, Any]:
        raw = raw_payload.strip()
        if not self._pattern:
            raise ValueError(
                f"Dynamic parser {self.parser_id} has invalid regex pattern"
            )

        m = self._pattern.search(raw)
        if not m:
            raise ValueError(
                f"Payload does not match dynamic template: {self.template_str}"
            )

        extracted = m.groupdict()
        parsed: dict[str, Any] = {
            "device_vendor": self.vendor,
            "device_product": self.product,
            "message": raw,
            "template_str": self.template_str,
        }

        # Apply mapping rules
        for rule in self.rules:
            val = extracted.get(rule.field_name)
            if val is None and rule.default_value is not None:
                val = rule.default_value

            if val is not None:
                transformed_val = self._apply_transform(val, rule.transform)
                parsed[rule.target_ocsf_field] = transformed_val

        # Default disposition / action normalization
        if "action" in parsed:
            act = str(parsed["action"]).lower()
            if act in ["deny", "drop", "block", "reject", "reset"]:
                parsed["disposition"] = "Blocked"
                parsed["disposition_id"] = 2
                parsed["severity"] = "Medium"
                parsed["severity_id"] = 3
            else:
                parsed["disposition"] = "Allowed"
                parsed["disposition_id"] = 1
                parsed["severity"] = "Informational"
                parsed["severity_id"] = 1
        elif "disposition" not in parsed:
            parsed["disposition"] = "Allowed"
            parsed["disposition_id"] = 1

        return parsed

    def _apply_transform(self, val: Any, transform: str | None) -> Any:
        if not transform:
            return val
        t = transform.lower()
        if t in ["to_int", "int", "integer"]:
            try:
                return int(val)
            except (ValueError, TypeError):
                return 0
        elif t in ["to_float", "float"]:
            try:
                return float(val)
            except (ValueError, TypeError):
                return 0.0
        elif t in ["to_upper", "upper"]:
            return str(val).upper()
        elif t in ["to_lower", "lower"]:
            return str(val).lower()
        elif t == "trim":
            return str(val).strip()
        return val
