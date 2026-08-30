"""
Base Parser Architecture & Interface
All parsers implement standard parsing contracts and metadata generation.
"""

import time
from abc import ABC, abstractmethod
from typing import Any

from ulpf.packages.schemas.models import (
    FormatType,
    ParserStatus,
    ParsingMetadata,
    SourceMetadata,
)


class BaseParser(ABC):
    """
    Abstract base class for all ULPF log parsers.
    Parses raw device logs into structured intermediate dictionary representations.
    """

    def __init__(
        self,
        parser_id: str,
        vendor: str,
        product: str,
        format_type: FormatType,
        version: str = "1.0.0",
        target_class: str = "Network Activity",
        target_class_uid: int = 4001,
        status: ParserStatus = ParserStatus.ACTIVE,
    ):
        self.parser_id = parser_id
        self.vendor = vendor
        self.product = product
        self.format_type = format_type
        self.version = version
        self.target_class = target_class
        self.target_class_uid = target_class_uid
        self.status = status

    @abstractmethod
    def matches(
        self, raw_payload: str, source_meta: SourceMetadata | None = None
    ) -> bool:
        """Determines if this parser can handle the given raw event."""

    @abstractmethod
    def parse_fields(
        self, raw_payload: str, source_meta: SourceMetadata | None = None
    ) -> dict[str, Any]:
        """Extracts key-value fields from the raw payload."""

    def parse(
        self, raw_payload: str, source_meta: SourceMetadata | None = None
    ) -> tuple[dict[str, Any], ParsingMetadata]:
        """
        Executes parsing with performance measurement and metadata generation.
        """
        start_t = time.perf_counter()
        errors = []
        parsed = {}
        try:
            parsed = self.parse_fields(raw_payload, source_meta)
        except Exception as e:
            errors.append(f"Parsing error in {self.parser_id}: {e!s}")

        duration_ms = (time.perf_counter() - start_t) * 1000.0

        meta = ParsingMetadata(
            parser_used=self.parser_id,
            parser_version=self.version,
            mapping_version="1.0.0",
            template_id=None,
            confidence=1.0 if not errors else 0.5,
            parse_duration_ms=round(duration_ms, 3),
            unparsed_fields={},
            errors=errors,
        )

        return parsed, meta
