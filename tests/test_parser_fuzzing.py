"""
Property-based and Adversarial Fuzz Testing with Hypothesis
Verifies that parsers and the end-to-end pipeline never crash or drop data when fed
malformed, truncated, null-byte injected, or adversarially crafted payloads.
"""

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from ulpf.packages.schemas.models import EventEnvelope
from ulpf.services.parser_engine.registry import ParserRegistry
from ulpf.services.pipeline_orchestrator import PipelineOrchestrator


@pytest.fixture(scope="module")
def orchestrator(tmp_path_factory):
    test_dir = tmp_path_factory.mktemp("fuzz_pipeline")
    return PipelineOrchestrator(base_dir=str(test_dir), enable_data_lake_auto_flush=False)


@pytest.fixture(scope="module")
def registry():
    return ParserRegistry()


# Fuzzing individual parsers directly
@settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow], deadline=None)
@given(st.text(min_size=0, max_size=1000))
def test_all_parsers_fuzz_direct_parsing(registry, text):
    """Feeds arbitrary text to all active parsers and confirms zero uncaught exceptions."""
    for parser in registry._parsers.values():
        try:
            parsed, meta = parser.parse(text)
            assert isinstance(parsed, dict)
            assert hasattr(meta, "errors")
            assert hasattr(meta, "confidence")
        except Exception as e:
            pytest.fail(f"Parser {parser.parser_id} crashed with unhandled exception on input: {text[:50]!r}: {e}")


# Adversarially crafted format prefixes with corrupt tails
CORRUPT_FORMAT_PREFIXES = [
    "CEF:0|Vendor|Product|1.0|",
    "LEEF:2.0|Vendor|Product|1.0|001|",
    "<166>Aug 27 10:15:30 fw-01 %ASA-6-302013: Built inbound TCP connection ",
    "<134>Aug 27 10:15:35 chkp-fw01 CheckPoint: action=",
    "date=2026-08-27 time=10:15:32 devname=\"FGT\" srcip=",
    '{"timestamp":"2026-08-27T10:15:33Z","flow_id":',
    '{"ts":1693131334.5,"id.orig_h":',
    "1693131336.120    15 192.168.1.100 TCP_DENIED/403 ",
    "[APPLIANCE-FW] 2026-08-27T10:15:40Z DEV=EDGE "
]


@settings(max_examples=40, suppress_health_check=[HealthCheck.too_slow], deadline=None)
@given(
    prefix=st.sampled_from(CORRUPT_FORMAT_PREFIXES),
    garbage=st.text(alphabet=st.characters(blacklist_categories=("Cs",)), min_size=1, max_size=300)
)
def test_pipeline_fuzz_corrupt_prefixes(orchestrator, prefix, garbage):
    """
    Feeds corrupt semi-valid payloads through the full PipelineOrchestrator.
    Guarantees the system lands in a valid normalized envelope or recorded error queue entry.
    """
    payload = prefix + garbage
    env = orchestrator.process_raw_log(payload, transport="fuzz_test")

    assert isinstance(env, EventEnvelope)
    assert env.event_id is not None
    assert env.raw.sha256 is not None
    assert len(env.raw.sha256) == 64

    # Either it was parsed into OCSF, or routed to Drain3 onboarding / error queue
    if env.ocsf is not None:
        assert "class_uid" in env.ocsf
        assert "metadata" in env.ocsf
    else:
        # Must be in onboarding queue or error queue
        assert env.parsing.parser_used in ["drain3-onboarding-queue", None] or len(env.parsing.errors) > 0


@settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow], deadline=None)
@given(
    payload=st.text(min_size=1, max_size=500).map(lambda t: t + "\x00'\"--;#%00\r\n\t")
)
def test_pipeline_fuzz_injection_characters(orchestrator, payload):
    """
    Feeds SQL/shell/null-byte special character strings and verifies safe handling.
    """
    env = orchestrator.process_raw_log(payload, transport="fuzz_injection")
    assert isinstance(env, EventEnvelope)
    assert env.raw.raw_payload == payload
