"""
Integration Tests: Drain3 Unknown Log Auto-Onboarding & Replay Lifecycle
"""

import shutil
import tempfile

import pytest

from ulpf.packages.schemas.models import OnboardingStatus
from ulpf.services.pipeline_orchestrator import PipelineOrchestrator


@pytest.fixture
def orchestrator():
    temp_dir = tempfile.mkdtemp()
    orch = PipelineOrchestrator(base_dir=temp_dir, enable_data_lake_auto_flush=False)
    yield orch
    shutil.rmtree(temp_dir, ignore_errors=True)


def test_unknown_log_onboarding_and_replay_flow(orchestrator):
    unseen_log_1 = '[APPLIANCE-FW] 2026-08-27T10:15:40Z DEV=EDGE-FW-09 RULE=BLOCK_SSH SRC=185.220.101.5:49152 DST=10.0.0.5:22 PROTO=TCP ACTION=DENY BYTES=120 REASON="BRUTE_FORCE_BURST"'
    unseen_log_2 = '[APPLIANCE-FW] 2026-08-27T10:15:41Z DEV=EDGE-FW-09 RULE=BLOCK_SSH SRC=185.220.101.8:50123 DST=10.0.0.5:22 PROTO=TCP ACTION=DENY BYTES=120 REASON="BRUTE_FORCE_BURST"'

    # 1. Ingest unseen log -> Should be routed to Drain3 Onboarding Queue
    env1 = orchestrator.process_raw_log(unseen_log_1)
    assert env1.parsing.parser_used == "drain3-onboarding-queue"

    # Ingest 2nd similar log
    env2 = orchestrator.process_raw_log(unseen_log_2)

    # 2. Check Onboarding Session
    sessions = orchestrator.onboarding_manager.list_sessions()
    assert len(sessions) == 1
    session = sessions[0]
    assert session["status"] == OnboardingStatus.PENDING.value
    assert len(session["variables"]) > 0

    # 3. Approve and Publish Dynamic Parser
    pub_res = orchestrator.onboarding_manager.approve_and_publish(
        session_id=session["session_id"],
        reviewed_by="test-reviewer",
        custom_parser_id="appliance-fw-custom-parser",
        version="1.0.0",
    )
    assert pub_res["success"] is True
    assert pub_res["parser_id"] == "appliance-fw-custom-parser"

    # 4. Now ingest a 3rd log of this format -> Should automatically normalize into OCSF!
    unseen_log_3 = '[APPLIANCE-FW] 2026-08-27T10:15:42Z DEV=EDGE-FW-09 RULE=PERMIT_WEB SRC=198.51.100.25:54321 DST=10.0.1.50:80 PROTO=TCP ACTION=ALLOW BYTES=4520 REASON="NORMAL_HTTP"'
    env3 = orchestrator.process_raw_log(unseen_log_3)

    assert env3.parsing.parser_used == "appliance-fw-custom-parser"
    assert env3.ocsf is not None
    assert env3.ocsf["class_uid"] == 4001
    assert env3.ocsf["src_endpoint"]["ip"] == "198.51.100.25"
    assert env3.ocsf["dst_endpoint"]["ip"] == "10.0.1.50"
    assert env3.ocsf["disposition_id"] == 1  # Allowed
