# ULPF Parser Development Guide
**Extending and Creating Parsers for the Universal Log Pre-processing Framework**

---

## 1. Parser Architecture

All parsers in ULPF inherit from `BaseParser` (`ulpf/services/parser_engine/base.py`) and implement two mandatory methods:
1. `matches(raw_payload: str, source_meta: Optional[SourceMetadata]) -> bool`
2. `parse_fields(raw_payload: str, source_meta: Optional[SourceMetadata]) -> Dict[str, Any]`

---

## 2. Writing a New Custom Parser

### Example: Bespoke Hardware Appliance Parser

```python
import re
from typing import Dict, Any, Optional
from ulpf.packages.schemas.models import FormatType, SourceMetadata
from ulpf.services.parser_engine.base import BaseParser

class CustomFirewallParser(BaseParser):
    def __init__(self):
        super().__init__(
            parser_id="custom-fw-parser",
            vendor="AcmeCorp",
            product="EdgeGuard",
            format_type=FormatType.PROPRIETARY,
            version="1.0.0",
            target_class="Network Activity",
            target_class_uid=4001
        )
        self.pattern = re.compile(r"\[ACME-FW\]\s+(\S+)\s+SRC=([0-9.]+):(\d+)\s+DST=([0-9.]+):(\d+)\s+ACTION=(\w+)")

    def matches(self, raw_payload: str, source_meta: Optional[SourceMetadata] = None) -> bool:
        return "[ACME-FW]" in raw_payload

    def parse_fields(self, raw_payload: str, source_meta: Optional[SourceMetadata] = None) -> Dict[str, Any]:
        m = self.pattern.search(raw_payload)
        if not m:
            raise ValueError("Payload does not match AcmeCorp format")

        return {
            "device_vendor": self.vendor,
            "device_product": self.product,
            "timestamp": m.group(1),
            "src_ip": m.group(2),
            "src_port": int(m.group(3)),
            "dst_ip": m.group(4),
            "dst_port": int(m.group(5)),
            "action": m.group(6).lower(),
            "disposition": "Blocked" if m.group(6).lower() in ["deny", "drop"] else "Allowed",
            "disposition_id": 2 if m.group(6).lower() in ["deny", "drop"] else 1
        }
```

---

## 3. Registering the Parser

Register the parser via code:
```python
orchestrator.parser_registry.register_parser_definition(p_def)
```
Or via the REST API (`POST /api/parsers`):
```json
{
  "parser_id": "custom-fw-parser",
  "vendor": "AcmeCorp",
  "product": "EdgeGuard",
  "format": "proprietary",
  "version": "1.0.0",
  "parser_type": "regex",
  "target_class": "Network Activity",
  "target_class_uid": 4001,
  "status": "ACTIVE"
}
```

---

## 4. Immutability & Version Lifecycle

- **Lifecycle States**: `DRAFT` $\rightarrow$ `TESTING` $\rightarrow$ `ACTIVE` $\rightarrow$ `DEPRECATED`.
- **Immutability Principle**: An active parser version cannot be overwritten in-place. Any change requires incrementing the version string (e.g. `1.0.0` $\rightarrow$ `1.1.0`).
