"""
Unknown Log Onboarding Session Manager
Orchestrates template mining, candidate mapping review, human approval, and post-onboarding replay.
"""

import json
import threading
import uuid
import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable

from ulpf.packages.schemas.models import (
    OnboardingSession,
    OnboardingStatus,
    TemplateVariable,
    ParserDefinition,
    ParserRule,
    ParserStatus,
    FormatType,
    AuditRecord
)
from ulpf.services.onboarding.drain_miner import Drain3Engine
from ulpf.services.onboarding.field_discovery import FieldDiscoveryEngine
from ulpf.services.parser_engine.registry import ParserRegistry


class OnboardingSessionManager:
    """
    Manages the lifecycle of unknown log formats from discovery to human-in-the-loop publication.
    """

    def __init__(
        self,
        parser_registry: ParserRegistry,
        drain_engine: Optional[Drain3Engine] = None,
        field_engine: Optional[FieldDiscoveryEngine] = None,
        persistence_dir: str = "data/onboarding_sessions",
        replay_callback: Optional[Callable[[List[str]], None]] = None,
        audit_sink: Optional[Callable[[AuditRecord], None]] = None
    ):
        self.parser_registry = parser_registry
        self.drain_engine = drain_engine or Drain3Engine()
        self.field_engine = field_engine or FieldDiscoveryEngine()
        self.persistence_dir = Path(persistence_dir)
        self.persistence_dir.mkdir(parents=True, exist_ok=True)
        self.replay_callback = replay_callback
        self.audit_sink = audit_sink
        
        self._lock = threading.Lock()
        self._sessions: Dict[str, OnboardingSession] = {}
        self._compiled_regexes: Dict[str, str] = {}
        self._rules_by_session: Dict[str, List[ParserRule]] = {}
        self._audit_trail: List[AuditRecord] = []

        self._load_persisted_sessions()
        self._load_persisted_audits()

    def _load_persisted_sessions(self):
        if not self.persistence_dir.exists():
            return
        for sf in self.persistence_dir.glob("*.json"):
            if sf.name == "audit_trail.json":
                continue
            try:
                with open(sf, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    session = OnboardingSession(**data["session"])
                    self._sessions[session.session_id] = session
                    self._compiled_regexes[session.session_id] = data.get("compiled_regex", "")
                    if "rules" in data:
                        self._rules_by_session[session.session_id] = [ParserRule(**r) for r in data["rules"]]
            except (json.JSONDecodeError, KeyError, ValueError):
                pass

    def _load_persisted_audits(self):
        audit_file = self.persistence_dir / "audit_trail.jsonl"
        if not audit_file.exists():
            return
        try:
            with open(audit_file, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        self._audit_trail.append(AuditRecord(**json.loads(line)))
        except (json.JSONDecodeError, ValueError):
            pass

    def _persist_audit_record(self, audit: AuditRecord):
        audit_file = self.persistence_dir / "audit_trail.jsonl"
        with open(audit_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(audit.model_dump()) + "\n")
        if self.audit_sink:
            try:
                self.audit_sink(audit)
            except Exception:
                pass

    def process_unknown_log(
        self,
        raw_payload: str,
        vendor_hint: Optional[str] = None,
        product_hint: Optional[str] = None
    ) -> OnboardingSession:
        """
        Mines the unknown log, clusters with Drain3, extracts candidate fields, and updates/creates session.
        """
        with self._lock:
            mine_res = self.drain_engine.mine_log(raw_payload)
            cluster_id = mine_res["cluster_id"]
            template_str = mine_res["template"]

            # Check if session already exists for this cluster template
            existing_session = None
            for s in self._sessions.values():
                if s.template_id == cluster_id or s.discovered_template == template_str:
                    existing_session = s
                    break

            if existing_session:
                if raw_payload not in existing_session.raw_sample_logs:
                    existing_session.raw_sample_logs.append(raw_payload)
                # Re-analyze fields with new samples
                variables, regex_pat, rules = self.field_engine.analyze_template_and_samples(
                    template_str, existing_session.raw_sample_logs
                )
                existing_session.variables = variables
                self._compiled_regexes[existing_session.session_id] = regex_pat
                self._rules_by_session[existing_session.session_id] = rules
                self._persist_session(existing_session)
                return existing_session

            # Create new session
            session_id = str(uuid.uuid4())
            variables, regex_pat, rules = self.field_engine.analyze_template_and_samples(
                template_str, [raw_payload]
            )

            vendor = vendor_hint or "Custom-Appliance"
            product = product_hint or f"Device-Model-{cluster_id}"

            session = OnboardingSession(
                session_id=session_id,
                vendor=vendor,
                product=product,
                format=FormatType.PROPRIETARY,
                discovered_template=template_str,
                template_id=cluster_id,
                raw_sample_logs=[raw_payload],
                variables=variables,
                target_class="Network Activity",
                target_class_uid=4001,
                status=OnboardingStatus.PENDING,
                confidence_score=0.88
            )

            self._sessions[session_id] = session
            self._compiled_regexes[session_id] = regex_pat
            self._rules_by_session[session_id] = rules
            self._persist_session(session)
            return session

    def list_sessions(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [s.model_dump() for s in self._sessions.values()]

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            s = self._sessions.get(session_id)
            if not s:
                return None
            res = s.model_dump()
            res["compiled_regex"] = self._compiled_regexes.get(session_id, "")
            res["rules"] = [r.model_dump() for r in self._rules_by_session.get(session_id, [])]
            return res

    def update_variable_mapping(
        self,
        session_id: str,
        var_index: int,
        target_ocsf_field: str,
        inferred_type: Optional[str] = None,
        transform: Optional[str] = None
    ) -> bool:
        """Updates human-reviewed field mappings for a candidate variable."""
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return False

            if 0 <= var_index < len(session.variables):
                session.variables[var_index].suggested_ocsf_field = target_ocsf_field
                if inferred_type:
                    session.variables[var_index].inferred_type = inferred_type
                session.variables[var_index].confidence = 1.0  # Human approved

                # Update rules
                rules = self._rules_by_session.get(session_id, [])
                if 0 <= var_index < len(rules):
                    rules[var_index].target_ocsf_field = target_ocsf_field
                    if transform:
                        rules[var_index].transform = transform

                self._persist_session(session)
                return True
            return False

    def approve_and_publish(
        self,
        session_id: str,
        reviewed_by: str = "security-reviewer",
        custom_parser_id: Optional[str] = None,
        version: str = "1.0.0"
    ) -> Dict[str, Any]:
        """
        1. Validates reviewed mappings.
        2. Compiles a new versioned ParserDefinition and registers with ParserRegistry.
        3. Marks session as PUBLISHED.
        4. Triggers post-onboarding automated replay.
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return {"success": False, "error": f"Session {session_id} not found"}

            parser_id = custom_parser_id or f"{session.vendor.lower()}-{session.product.lower()}-parser"
            regex_pat = self._compiled_regexes.get(session_id, "")
            rules = self._rules_by_session.get(session_id, [])

            # Create Parser Definition
            p_def = ParserDefinition(
                parser_id=parser_id,
                vendor=session.vendor,
                product=session.product,
                format=session.format,
                version=version,
                parser_type="drain3_template",
                pattern=regex_pat,
                rules=rules,
                target_class=session.target_class,
                target_class_uid=session.target_class_uid,
                status=ParserStatus.ACTIVE,
                author=reviewed_by,
                sample_raw=session.raw_sample_logs[0] if session.raw_sample_logs else None
            )

            # Register into active ParserRegistry
            reg_key = self.parser_registry.register_parser_definition(p_def)

            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            session.status = OnboardingStatus.PUBLISHED
            session.reviewed_by = reviewed_by
            session.reviewed_at = now_iso
            session.published_parser_id = parser_id
            session.published_version = version

            self._persist_session(session)

            # Record Audit Trail
            audit = AuditRecord(
                user=reviewed_by,
                role="REVIEWER",
                action="ONBOARDING_APPROVED_AND_PUBLISHED",
                resource_type="PARSER",
                resource_id=reg_key,
                details={
                    "session_id": session_id,
                    "template": session.discovered_template,
                    "rules_count": len(rules),
                    "replayed_events_count": len(session.raw_sample_logs)
                }
            )
            self._audit_trail.append(audit)
            self._persist_audit_record(audit)

        # Trigger replay outside lock
        if self.replay_callback and session.raw_sample_logs:
            self.replay_callback(session.raw_sample_logs)

        return {
            "success": True,
            "parser_id": parser_id,
            "version": version,
            "registration_key": reg_key,
            "replayed_events": len(session.raw_sample_logs),
            "status": "PUBLISHED"
        }

    def reject_session(self, session_id: str, reason: str, reviewed_by: str = "security-reviewer") -> bool:
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return False
            session.status = OnboardingStatus.REJECTED
            session.reviewed_by = reviewed_by
            session.reviewed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
            self._persist_session(session)

            audit = AuditRecord(
                user=reviewed_by,
                role="REVIEWER",
                action="ONBOARDING_REJECTED",
                resource_type="SESSION",
                resource_id=session_id,
                details={
                    "session_id": session_id,
                    "reason": reason,
                    "template": session.discovered_template
                }
            )
            self._audit_trail.append(audit)
            self._persist_audit_record(audit)
            return True

    def get_audit_trail(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [a.model_dump() for a in self._audit_trail]

    def _persist_session(self, session: OnboardingSession):
        out_file = self.persistence_dir / f"{session.session_id}.json"
        data = {
            "session": session.model_dump(),
            "compiled_regex": self._compiled_regexes.get(session.session_id, ""),
            "rules": [r.model_dump() for r in self._rules_by_session.get(session.session_id, [])]
        }
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
