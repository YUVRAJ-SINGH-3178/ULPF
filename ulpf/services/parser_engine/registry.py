"""
Modular Parser Registry & Lifecycle Management
Maintains active, testing, draft, and deprecated parsers with version control and dynamic discovery.
"""

import json
import threading
from pathlib import Path
from typing import Any

from ulpf.packages.schemas.models import (
    ParserDefinition,
    ParserStatus,
    SourceMetadata,
)
from ulpf.services.parser_engine.base import BaseParser
from ulpf.services.parser_engine.cef_parser import CEFParser
from ulpf.services.parser_engine.checkpoint_parser import CheckpointParser
from ulpf.services.parser_engine.cisco_asa_parser import CiscoASAParser
from ulpf.services.parser_engine.drain3_dynamic_parser import Drain3DynamicParser
from ulpf.services.parser_engine.fortinet_parser import FortinetParser
from ulpf.services.parser_engine.generic_parsers import (
    GenericJSONParser,
    GenericRFC3164Parser,
    GenericRFC5424Parser,
)
from ulpf.services.parser_engine.leef_parser import LEEFParser
from ulpf.services.parser_engine.palo_alto_parser import PaloAltoParser
from ulpf.services.parser_engine.squid_parser import SquidProxyParser
from ulpf.services.parser_engine.suricata_json_parser import SuricataEVEParser
from ulpf.services.parser_engine.zeek_parser import ZeekConnParser


class ParserRegistry:
    """
    Thread-safe catalog of log parsers with immutable versioning and lifecycle controls.
    """

    def __init__(self, persistence_dir: str = "data/parsers"):
        self.persistence_dir = Path(persistence_dir)
        self.persistence_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._parsers: dict[str, BaseParser] = {}
        self._parser_defs: dict[str, ParserDefinition] = {}

        self._register_default_parsers()
        self._load_persisted_parsers()

    def _register_default_parsers(self):
        """Registers built-in parsers."""
        defaults: list[BaseParser] = [
            CiscoASAParser(),
            PaloAltoParser(),
            FortinetParser(),
            CheckpointParser(),
            SuricataEVEParser(),
            ZeekConnParser(),
            SquidProxyParser(),
            CEFParser(),
            LEEFParser(),
            GenericRFC5424Parser(),
            GenericRFC3164Parser(),
            GenericJSONParser(),
        ]
        for p in defaults:
            self._parsers[f"{p.parser_id}:{p.version}"] = p
            self._parser_defs[f"{p.parser_id}:{p.version}"] = ParserDefinition(
                parser_id=p.parser_id,
                vendor=p.vendor,
                product=p.product,
                format=p.format_type,
                version=p.version,
                parser_type="native",
                target_class=p.target_class,
                target_class_uid=p.target_class_uid,
                status=p.status,
                author="system"
            )

    def _load_persisted_parsers(self):
        """Loads custom and dynamic parsers from disk."""
        if not self.persistence_dir.exists():
            return
        for json_file in self.persistence_dir.glob("*.json"):
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    p_def = ParserDefinition(**data)
                    key = f"{p_def.parser_id}:{p_def.version}"
                    self._parser_defs[key] = p_def

                    if p_def.pattern:
                        dyn_parser = Drain3DynamicParser(
                            parser_id=p_def.parser_id,
                            vendor=p_def.vendor,
                            product=p_def.product,
                            version=p_def.version,
                            template_str=p_def.pattern,
                            compiled_regex=p_def.pattern,
                            rules=p_def.rules,
                            target_class=p_def.target_class,
                            target_class_uid=p_def.target_class_uid,
                            status=p_def.status
                        )
                        self._parsers[key] = dyn_parser
            except Exception:
                pass

    def register_parser_definition(self, p_def: ParserDefinition) -> str:
        """
        Registers a new versioned parser definition and writes to disk.
        Active versions cannot be overwritten.
        """
        with self._lock:
            key = f"{p_def.parser_id}:{p_def.version}"
            if key in self._parsers and self._parsers[key].status == ParserStatus.ACTIVE:
                raise ValueError(f"Cannot overwrite active parser {key}. Please publish a new version increment (e.g. 1.1.0).")

            self._parser_defs[key] = p_def

            if p_def.pattern:
                dyn_parser = Drain3DynamicParser(
                    parser_id=p_def.parser_id,
                    vendor=p_def.vendor,
                    product=p_def.product,
                    version=p_def.version,
                    template_str=p_def.pattern,
                    compiled_regex=p_def.pattern,
                    rules=p_def.rules,
                    target_class=p_def.target_class,
                    target_class_uid=p_def.target_class_uid,
                    status=p_def.status
                )
                self._parsers[key] = dyn_parser

            # Persist to disk
            out_file = self.persistence_dir / f"{p_def.parser_id}_v{p_def.version.replace('.', '_')}.json"
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(p_def.model_dump(), f, indent=2)

            return key

    def find_parser(self, raw_payload: str, source_meta: SourceMetadata | None = None) -> BaseParser | None:
        """
        Finds the best matching ACTIVE parser for a given raw payload.
        Prioritizes specific vendor parsers over generic fallbacks.
        """
        with self._lock:
            active_parsers = [p for p in self._parsers.values() if p.status == ParserStatus.ACTIVE]

        # 1. First check specific vendor/product parsers
        specific_parsers = [p for p in active_parsers if not p.parser_id.startswith("generic") and not p.parser_id.startswith("syslog-rfc")]
        for parser in specific_parsers:
            if parser.matches(raw_payload, source_meta):
                return parser

        # 2. Check dynamic/onboarded parsers
        dynamic_parsers = [p for p in active_parsers if isinstance(p, Drain3DynamicParser)]
        for parser in dynamic_parsers:
            if parser.matches(raw_payload, source_meta):
                return parser

        # 3. Check generic parsers
        generic_parsers = [p for p in active_parsers if p.parser_id.startswith("generic") or p.parser_id.startswith("syslog-rfc") or p.parser_id in ["cef-standard-parser", "leef-standard-parser"]]
        for parser in generic_parsers:
            if parser.matches(raw_payload, source_meta):
                return parser

        return None

    def get_parser(self, parser_id: str, version: str | None = None) -> BaseParser | None:
        with self._lock:
            if version:
                return self._parsers.get(f"{parser_id}:{version}")
            # Get latest version
            matches = [p for k, p in self._parsers.items() if p.parser_id == parser_id]
            if matches:
                return matches[-1]
            return None

    def list_parsers(self) -> list[dict[str, Any]]:
        with self._lock:
            result = []
            for key, p_def in self._parser_defs.items():
                result.append(p_def.model_dump())
            return result

    def test_parser(self, parser_id: str, sample_payload: str, version: str | None = None) -> dict[str, Any]:
        parser = self.get_parser(parser_id, version)
        if not parser:
            return {"success": False, "error": f"Parser {parser_id} not found"}

        parsed_fields, meta = parser.parse(sample_payload)
        return {
            "success": len(meta.errors) == 0,
            "parser_id": parser.parser_id,
            "version": parser.version,
            "parsed_fields": parsed_fields,
            "errors": meta.errors,
            "parse_duration_ms": meta.parse_duration_ms
        }
