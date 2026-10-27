import uuid
import os
import json
import logging
import threading
import copy
from datetime import datetime, timezone
from contextlib import contextmanager
from typing import Dict, List, Optional, Any, Set, Tuple
from backend.correlator.models import (
    TokenRecord,
    TokenReuseRecord,
    DetectionRecord,
    TokenStatus,
    AlertRecord,
    AlertStatus,
    AlertSeverity,
    RULE_TOKEN_REUSE,
    RULE_REVOKED_USE,
    RULE_EXPIRED_USE,
    RULE_CONCURRENT_USE,
    RULE_IMPOSSIBLE_TRAVEL,
    RULE_TITLES,
    RULE_SEVERITIES,
    DETECTION_TYPE_TO_RULE,
    RULE_TO_DETECTION_TYPE,
    redact_secrets,
)

logger = logging.getLogger("tokenline.correlator.engine")

_transaction_context = threading.local()


def is_in_transaction() -> bool:
    """Returns True if the current thread is within an active correlator transaction."""
    return getattr(_transaction_context, "active", False)


def parse_timestamp(ts: Any) -> Optional[datetime]:
    """
    Parses ISO-8601 strings, short fixture strings (HH:MM or HH:MM:SS), or datetime objects
    into timezone-aware UTC datetime instances.
    """
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(timezone.utc)
    if not isinstance(ts, str):
        return None
    s = ts.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        try:
            parts = s.split(":")
            if len(parts) >= 2:
                hour = int(parts[0])
                minute = int(parts[1])
                second = int(parts[2]) if len(parts) > 2 else 0
                return datetime(2026, 1, 1, hour, minute, second, tzinfo=timezone.utc)
        except Exception:
            return None
    return None


class TokenFamilyCorrelator:
    """
    Unified Token-Family Correlator & State-Machine Engine.
    Reconstructs refresh-token parent/child chains into token families,
    maintains lifecycle states (ACTIVE, ROTATED, REVOKED, EXPIRED, REUSED),
    and evaluates production detection rules for:
      - Refresh-token reuse
      - Revoked-token use
      - Expired-token use
      - Concurrent use
      - Impossible travel
    Provides idempotent, thread-safe correlation across concurrent and replayed events.
    """

    def __init__(self):
        self._lock = threading.RLock()
        # Key: token_hash -> TokenRecord
        self.tokens: Dict[str, TokenRecord] = {}
        # Key: token_family -> List[token_hash]
        self.families: Dict[str, List[str]] = {}
        # List of detected reuse occurrences (TokenReuseRecord)
        self.reuse_records: List[TokenReuseRecord] = []
        # Set of (token_hash, attempted_event_id) pairs to guarantee idempotent reuse recording
        self._reuse_seen: Set[Tuple[str, str]] = set()
        # List of all detected violations (DetectionRecord)
        self.detection_records: List[DetectionRecord] = []
        # Deduplication set of (detection_type, token_hash, attempted_event_id)
        self._detections_seen: Set[Tuple[str, str, str]] = set()
        # Standardized alert instances (AlertRecord)
        self.alerts: List[AlertRecord] = []
        # Deduplication set of alert fingerprints: "rule_id:token_hash:event_id"
        self._alerts_seen: Set[str] = set()
        # Token usage history: token_hash -> List[Dict[str, Any]]
        self._token_usages: Dict[str, List[Dict[str, Any]]] = {}
        # User usage history: user_id -> List[Dict[str, Any]]
        self._user_usages: Dict[str, List[Dict[str, Any]]] = {}

    def clear(self):
        """Clears in-memory correlation state thread-safely."""
        with self._lock:
            self.tokens.clear()
            self.families.clear()
            self.reuse_records.clear()
            self._reuse_seen.clear()
            self.detection_records.clear()
            self._detections_seen.clear()
            self.alerts.clear()
            self._alerts_seen.clear()
            self._token_usages.clear()
            self._user_usages.clear()

    def _snapshot(self) -> Dict[str, Any]:
        """Captures a deep copy of all in-memory correlation state."""
        return {
            "tokens": copy.deepcopy(self.tokens),
            "families": copy.deepcopy(self.families),
            "reuse_records": copy.deepcopy(self.reuse_records),
            "_reuse_seen": copy.copy(self._reuse_seen),
            "detection_records": copy.deepcopy(self.detection_records),
            "_detections_seen": copy.copy(self._detections_seen),
            "alerts": copy.deepcopy(self.alerts),
            "_alerts_seen": copy.copy(self._alerts_seen),
            "_token_usages": copy.deepcopy(self._token_usages),
            "_user_usages": copy.deepcopy(self._user_usages),
        }

    def _restore(self, snap: Dict[str, Any]):
        """Restores in-memory correlation state from a snapshot."""
        self.tokens = snap["tokens"]
        self.families = snap["families"]
        self.reuse_records = snap["reuse_records"]
        self._reuse_seen = snap["_reuse_seen"]
        self.detection_records = snap.get("detection_records", [])
        self._detections_seen = snap.get("_detections_seen", set())
        self.alerts = snap.get("alerts", [])
        self._alerts_seen = snap.get("_alerts_seen", set())
        self._token_usages = snap.get("_token_usages", {})
        self._user_usages = snap.get("_user_usages", {})

    def _record_alert(
        self,
        rule_id: str,
        token_family_id: str,
        event_refs: List[str],
        timestamp: str,
        severity: Optional[str] = None,
        title: Optional[str] = None,
        explanation: Optional[str] = None,
        evidence: Optional[Dict[str, Any]] = None,
        token_hash: Optional[str] = None,
        user_id: Optional[str] = None,
        status: str = AlertStatus.OPEN.value,
    ) -> AlertRecord:
        """
        Records an evidence-based AlertRecord idempotently.
        Deduplicates in-memory by dedup_fingerprint and keeps detection_records in sync for compatibility.
        """
        ref = event_refs[0] if event_refs else "noref"
        th = token_hash or "nohash"
        fingerprint = f"{rule_id}:{th}:{ref}"

        if fingerprint in self._alerts_seen:
            for a in self.alerts:
                if a.dedup_fingerprint == fingerprint:
                    return a

        alert = AlertRecord(
            id=f"alert-{uuid.uuid4().hex[:12]}",
            rule_id=rule_id,
            severity=severity or RULE_SEVERITIES.get(rule_id, AlertSeverity.HIGH.value),
            timestamp=timestamp,
            status=status,
            event_refs=list(event_refs),
            token_family_id=token_family_id,
            token_hash=token_hash,
            user_id=user_id,
            title=title or RULE_TITLES.get(rule_id, f"Security Alert: {rule_id}"),
            explanation=explanation or "",
            evidence=evidence or {},
            dedup_fingerprint=fingerprint,
            created_at=timestamp,
            updated_at=timestamp,
        )
        self.alerts.append(alert)
        self._alerts_seen.add(fingerprint)

        # Synchronize into detection_records for backward compatibility
        det_type = RULE_TO_DETECTION_TYPE.get(rule_id, rule_id)
        det_key = (det_type, token_hash or "", ref)
        if det_key not in self._detections_seen:
            det = DetectionRecord(
                detection_type=det_type,
                token_hash=token_hash or "",
                token_family=token_family_id,
                detected_at=timestamp,
                attempted_event_id=ref,
                severity=alert.severity,
                user_id=user_id,
                chain_context=evidence.get("chain_context", []) if evidence else [],
                metadata=alert.evidence,
            )
            self.detection_records.append(det)
            self._detections_seen.add(det_key)

        return alert

    def _record_detection(
        self,
        detection_type: str,
        token_hash: str,
        token_family: str,
        detected_at: str,
        attempted_event_id: str,
        severity: str = "high",
        parent_token_hash: Optional[str] = None,
        user_id: Optional[str] = None,
        chain_context: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> DetectionRecord:
        """Records a detection record idempotently, delegating to standardized AlertRecord."""
        rule_id = DETECTION_TYPE_TO_RULE.get(detection_type, detection_type)
        ev = dict(metadata or {})
        if parent_token_hash:
            ev["parent_token_hash"] = parent_token_hash
        if chain_context:
            ev["chain_context"] = chain_context

        explanation = ""
        if rule_id == RULE_TOKEN_REUSE:
            explanation = f"Refresh token {token_hash[:8]}... was presented after prior rotation in family {token_family}."
        elif rule_id == RULE_REVOKED_USE:
            explanation = f"Revoked token {token_hash[:8]}... was presented for authentication in family {token_family}."
        elif rule_id == RULE_EXPIRED_USE:
            explanation = f"Expired token {token_hash[:8]}... was presented for authentication in family {token_family}."
        elif rule_id == RULE_CONCURRENT_USE:
            explanation = f"Token {token_hash[:8]}... was used concurrently from different client contexts within 60s."
        elif rule_id == RULE_IMPOSSIBLE_TRAVEL:
            explanation = f"Geographically impossible travel observed for user {user_id} within 300s."

        self._record_alert(
            rule_id=rule_id,
            token_family_id=token_family,
            event_refs=[attempted_event_id],
            timestamp=detected_at,
            severity=severity,
            title=RULE_TITLES.get(rule_id),
            explanation=explanation,
            evidence=ev,
            token_hash=token_hash,
            user_id=user_id,
        )

        for d in self.detection_records:
            if d.detection_type == detection_type and d.token_hash == token_hash and d.attempted_event_id == attempted_event_id:
                return d

        return DetectionRecord(
            detection_type=detection_type,
            token_hash=token_hash,
            token_family=token_family,
            detected_at=detected_at,
            attempted_event_id=attempted_event_id,
            severity=severity,
            parent_token_hash=parent_token_hash,
            user_id=user_id,
            chain_context=chain_context or [],
            metadata=metadata or {},
        )

    def get_detection_records(
        self,
        detection_type: Optional[str] = None,
        token_family: Optional[str] = None,
        token_hash: Optional[str] = None,
    ) -> List[DetectionRecord]:
        """Returns recorded detection records, optionally filtered."""
        with self._lock:
            results = list(self.detection_records)
            if detection_type:
                results = [r for r in results if r.detection_type == detection_type]
            if token_family:
                results = [r for r in results if r.token_family == token_family]
            if token_hash:
                results = [r for r in results if r.token_hash == token_hash]
            return results

    def get_alerts(
        self,
        rule_id: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        token_family_id: Optional[str] = None,
        token_hash: Optional[str] = None,
        db_session: Optional[Any] = None,
    ) -> List[AlertRecord]:
        """
        Returns recorded standardized alerts, optionally filtered.
        Retrieves from database when db_session is provided, otherwise from in-memory store.
        """
        if db_session is not None:
            from backend.collector.db import Alert as DBAlert
            query = db_session.query(DBAlert)
            if rule_id:
                query = query.filter(DBAlert.rule_id == rule_id)
            if severity:
                query = query.filter(DBAlert.severity == severity)
            if status:
                query = query.filter(DBAlert.status == status)
            if token_family_id:
                query = query.filter(DBAlert.token_family_id == token_family_id)
            if token_hash:
                query = query.filter(DBAlert.token_hash == token_hash)
            db_rows = query.order_by(DBAlert.timestamp.asc()).all()
            return [
                AlertRecord(
                    id=row.id,
                    rule_id=row.rule_id,
                    severity=row.severity,
                    timestamp=row.timestamp,
                    status=row.status,
                    event_refs=json.loads(row.event_refs_json or "[]"),
                    token_family_id=row.token_family_id,
                    token_hash=row.token_hash,
                    user_id=row.user_id,
                    title=row.title,
                    explanation=row.explanation or "",
                    evidence=json.loads(row.evidence_json or "{}"),
                    dedup_fingerprint=row.dedup_fingerprint,
                    created_at=row.created_at,
                    updated_at=row.updated_at,
                )
                for row in db_rows
            ]

        with self._lock:
            results = list(self.alerts)
            if rule_id:
                results = [r for r in results if r.rule_id == rule_id]
            if severity:
                results = [r for r in results if r.severity == severity]
            if status:
                results = [r for r in results if r.status == status]
            if token_family_id:
                results = [r for r in results if r.token_family_id == token_family_id]
            if token_hash:
                results = [r for r in results if r.token_hash == token_hash]
            return results

    def update_alert_status(
        self,
        alert_id: str,
        new_status: str,
        db_session: Optional[Any] = None,
        commit: bool = True,
    ) -> Optional[AlertRecord]:
        """
        Updates the lifecycle status of an alert with validation:
        open -> acknowledged -> resolved.
        Rejects invalid transitions or invalid status names.
        """
        valid_statuses = {s.value for s in AlertStatus}
        if new_status not in valid_statuses:
            raise ValueError(f"Invalid alert status: '{new_status}'. Allowed statuses: {sorted(valid_statuses)}")

        now_iso = datetime.now(timezone.utc).isoformat()
        updated_alert: Optional[AlertRecord] = None

        with self._lock:
            # Check in-memory alert
            for a in self.alerts:
                if a.id == alert_id:
                    if a.status == new_status:
                        return a
                    if a.status == AlertStatus.RESOLVED.value and new_status != AlertStatus.RESOLVED.value:
                        raise ValueError(f"Cannot transition alert from terminal status '{a.status}' to '{new_status}'")
                    a.status = new_status
                    a.updated_at = now_iso
                    updated_alert = a
                    break

        if db_session is not None:
            from backend.collector.db import Alert as DBAlert
            db_alert = db_session.query(DBAlert).filter(DBAlert.id == alert_id).first()
            if db_alert:
                if db_alert.status == AlertStatus.RESOLVED.value and new_status != AlertStatus.RESOLVED.value:
                    raise ValueError(f"Cannot transition alert from terminal status '{db_alert.status}' to '{new_status}'")
                db_alert.status = new_status
                db_alert.updated_at = now_iso
                if commit:
                    db_session.commit()
                else:
                    db_session.flush()

                if not updated_alert:
                    updated_alert = AlertRecord(
                        id=db_alert.id,
                        rule_id=db_alert.rule_id,
                        severity=db_alert.severity,
                        timestamp=db_alert.timestamp,
                        status=db_alert.status,
                        event_refs=json.loads(db_alert.event_refs_json or "[]"),
                        token_family_id=db_alert.token_family_id,
                        token_hash=db_alert.token_hash,
                        user_id=db_alert.user_id,
                        title=db_alert.title,
                        explanation=db_alert.explanation or "",
                        evidence=json.loads(db_alert.evidence_json or "{}"),
                        dedup_fingerprint=db_alert.dedup_fingerprint,
                        created_at=db_alert.created_at,
                        updated_at=db_alert.updated_at,
                    )

        return updated_alert

    @contextmanager
    def transaction(self):
        """
        Context manager ensuring thread-safe atomic in-memory state changes.
        Rolls back in-memory structures to the snapshot taken at context entry if an error occurs.
        """
        with self._lock:
            prev = getattr(_transaction_context, "active", False)
            _transaction_context.active = True
            snap = self._snapshot()
            try:
                yield self
            except Exception:
                self._restore(snap)
                raise
            finally:
                _transaction_context.active = prev

    def process_event(
        self,
        event_data: Dict[str, Any],
        db_session: Optional[Any] = None,
        commit: Optional[bool] = None
    ) -> Optional[Any]:
        """
        Processes a schema-valid TokenLine authentication event idempotently.
        Updates internal token family state machine and flags violations if detected.
        Optionally persists/syncs to database if a db_session is provided.
        """
        if commit is None:
            commit = not is_in_transaction()

        with self._lock:
            snap = self._snapshot() if not is_in_transaction() else None
            try:
                return self._process_event_internal(event_data, db_session, commit=commit)
            except Exception:
                if snap is not None:
                    self._restore(snap)
                raise

    def _process_event_internal(
        self,
        event_data: Dict[str, Any],
        db_session: Optional[Any] = None,
        commit: bool = True
    ) -> Optional[Any]:
        event_id = event_data.get("event_id", "")
        event_type = event_data.get("event_type", "")
        time = event_data.get("time", "")
        user_id = event_data.get("user_id") or "unknown"
        token_hash = event_data.get("token_hash")
        parent_token_hash = event_data.get("parent_token_hash")
        event_token_family = event_data.get("token_family")
        device_id = event_data.get("device_id")
        ip_hash = event_data.get("ip_hash")
        country = event_data.get("country")
        endpoint = event_data.get("endpoint")

        if not token_hash:
            return None

        dt_event = parse_timestamp(time)

        detected_reuse: Optional[TokenReuseRecord] = None
        detected_violation: Optional[DetectionRecord] = None

        # ---------------------------------------------------------
        # 1. Target Token Identification & Verification
        # ---------------------------------------------------------
        # When refreshing, client presents parent_token_hash as evidence of lineage.
        # In usage/revocation/expiration, client presents token_hash.
        target_check = None
        if event_type == "token_refreshed" and parent_token_hash:
            target_check = parent_token_hash
        elif event_type not in ("token_issued", "logout", "token_revoked", "token_expired"):
            target_check = token_hash

        target_record = self.tokens.get(target_check) if target_check else None

        # ---------------------------------------------------------
        # 2. DETECTION RULES
        # ---------------------------------------------------------

        # Rule A: Refresh-token reuse on rotated tokens
        if target_check:
            if db_session is not None:
                from backend.collector.db import TokenFamilyMember as DBTokenFamilyMember, TokenReuseRecord as DBTokenReuseRecord
                existing_db = db_session.query(DBTokenFamilyMember).filter(DBTokenFamilyMember.token_hash == target_check).first()
                if existing_db and existing_db.is_rotated:
                    if event_type == "token_refreshed" and existing_db.superseded_by == token_hash:
                        # Legitimate replay of prior rotation
                        pass
                    else:
                        reuse_key = (target_check, event_id)
                        existing_reuse_db = db_session.query(DBTokenReuseRecord).filter(
                            DBTokenReuseRecord.token_hash == target_check,
                            DBTokenReuseRecord.attempted_event_id == event_id
                        ).first()

                        if existing_reuse_db:
                            detected_reuse = TokenReuseRecord(
                                token_hash=existing_reuse_db.token_hash,
                                token_family=existing_reuse_db.token_family,
                                reused_at=existing_reuse_db.reused_at,
                                attempted_event_id=existing_reuse_db.attempted_event_id,
                                parent_token_hash=existing_db.parent_token_hash,
                                user_id=user_id or existing_db.user_id,
                                chain_context=[],
                                metadata={
                                    "event_type": event_type,
                                    "device_id": device_id,
                                    "ip_hash": ip_hash,
                                    "endpoint": endpoint,
                                }
                            )
                        else:
                            detected_reuse = TokenReuseRecord(
                                token_hash=target_check,
                                token_family=existing_db.token_family,
                                reused_at=time,
                                attempted_event_id=event_id,
                                parent_token_hash=existing_db.parent_token_hash,
                                user_id=user_id or existing_db.user_id,
                                chain_context=[],
                                metadata={
                                    "event_type": event_type,
                                    "device_id": device_id,
                                    "ip_hash": ip_hash,
                                    "endpoint": endpoint,
                                }
                            )
                        if reuse_key not in self._reuse_seen:
                            self.reuse_records.append(detected_reuse)
                            self._reuse_seen.add(reuse_key)

                        # Record in unified detections
                        self._record_detection(
                            detection_type="refresh_reuse",
                            token_hash=target_check,
                            token_family=existing_db.token_family,
                            detected_at=time,
                            attempted_event_id=event_id,
                            severity="critical",
                            parent_token_hash=existing_db.parent_token_hash,
                            user_id=user_id or existing_db.user_id,
                            chain_context=[],
                            metadata=detected_reuse.metadata,
                        )

            elif target_record and target_record.is_rotated and target_record.status not in (TokenStatus.REVOKED, TokenStatus.EXPIRED):
                if event_type == "token_refreshed" and target_record.superseded_by == token_hash:
                    # Legitimate replay of prior rotation
                    pass
                else:
                    reuse_key = (target_check, event_id)
                    if reuse_key in self._reuse_seen:
                        for r in self.reuse_records:
                            if r.token_hash == target_check and r.attempted_event_id == event_id:
                                detected_reuse = r
                                break
                    else:
                        chain = self._walk_forward_unlocked(self._find_root_unlocked(target_check))
                        detected_reuse = TokenReuseRecord(
                            token_hash=target_check,
                            token_family=target_record.token_family,
                            reused_at=time,
                            attempted_event_id=event_id,
                            parent_token_hash=target_record.parent_token_hash,
                            user_id=user_id or target_record.user_id,
                            chain_context=chain,
                            metadata={
                                "event_type": event_type,
                                "device_id": device_id,
                                "ip_hash": ip_hash,
                                "endpoint": endpoint,
                            }
                        )
                        self.reuse_records.append(detected_reuse)
                        self._reuse_seen.add(reuse_key)

                    target_record.status = TokenStatus.REUSED
                    # Invalidate entire family upon refresh-token reuse
                    if target_record.token_family in self.families:
                        for th in self.families[target_record.token_family]:
                            if th in self.tokens:
                                self.tokens[th].status = TokenStatus.REVOKED
                                self.tokens[th].revoked_at = time
                                self.tokens[th].metadata["revoked_at"] = time
                    target_record.status = TokenStatus.REUSED

                    # Record in unified detections
                    self._record_detection(
                        detection_type="refresh_reuse",
                        token_hash=target_check,
                        token_family=target_record.token_family,
                        detected_at=time,
                        attempted_event_id=event_id,
                        severity="critical",
                        parent_token_hash=target_record.parent_token_hash,
                        user_id=user_id or target_record.user_id,
                        chain_context=self._walk_forward_unlocked(self._find_root_unlocked(target_check)),
                        metadata=detected_reuse.metadata if detected_reuse else {},
                    )

        # Rule B: Revoked-token use detection
        if target_record and target_record.status == TokenStatus.REVOKED and event_type not in ("token_revoked", "logout"):
            dt_rev = parse_timestamp(target_record.revoked_at or target_record.metadata.get("revoked_at"))
            # If the event occurred strictly before revocation timestamp, it was valid when sent (out of order delivery)
            if dt_event and dt_rev and dt_event < dt_rev:
                pass
            else:
                det = self._record_detection(
                    detection_type="revoked_token_use",
                    token_hash=target_check,
                    token_family=target_record.token_family,
                    detected_at=time,
                    attempted_event_id=event_id,
                    severity="high",
                    parent_token_hash=target_record.parent_token_hash,
                    user_id=user_id or target_record.user_id,
                    chain_context=self._walk_forward_unlocked(self._find_root_unlocked(target_check)),
                    metadata={
                        "revoked_at": target_record.revoked_at or target_record.metadata.get("revoked_at"),
                        "attempted_at": time,
                        "event_type": event_type,
                        "device_id": device_id,
                        "ip_hash": ip_hash,
                    }
                )
                if not detected_violation:
                    detected_violation = det

        # Rule C: Expired-token use detection
        if target_record and target_record.status == TokenStatus.EXPIRED and event_type not in ("token_expired", "token_issued"):
            dt_exp = parse_timestamp(target_record.expired_at or target_record.metadata.get("expired_at"))
            # If the event occurred strictly before expiration timestamp, it was valid when sent
            if dt_event and dt_exp and dt_event < dt_exp:
                pass
            else:
                det = self._record_detection(
                    detection_type="expired_token_use",
                    token_hash=target_check,
                    token_family=target_record.token_family,
                    detected_at=time,
                    attempted_event_id=event_id,
                    severity="high",
                    parent_token_hash=target_record.parent_token_hash,
                    user_id=user_id or target_record.user_id,
                    chain_context=self._walk_forward_unlocked(self._find_root_unlocked(target_check)),
                    metadata={
                        "expired_at": target_record.expired_at or target_record.metadata.get("expired_at"),
                        "attempted_at": time,
                        "event_type": event_type,
                        "device_id": device_id,
                        "ip_hash": ip_hash,
                    }
                )
                if not detected_violation:
                    detected_violation = det

        # Rule D: Concurrent-use detection (suspicious overlapping token use from distinct devices/IPs)
        if event_type in ("token_used", "token_refreshed", "login", "suspicious_device"):
            if token_hash in self._token_usages and dt_event:
                for prev in reversed(self._token_usages[token_hash]):
                    if prev["event_id"] == event_id:
                        continue
                    dt_prev = prev.get("datetime")
                    if dt_prev:
                        dt_sec = abs((dt_event - dt_prev).total_seconds())
                        if dt_sec <= 60:
                            prev_dev = prev.get("device_id")
                            prev_ip = prev.get("ip_hash")
                            # Trigger only if from different device or different IP
                            if (device_id and prev_dev and device_id != prev_dev) or (ip_hash and prev_ip and ip_hash != prev_ip):
                                fam = (target_record.token_family if target_record else event_token_family) or f"family-{uuid.uuid4().hex[:8]}"
                                det = self._record_detection(
                                    detection_type="concurrent_use",
                                    token_hash=token_hash,
                                    token_family=fam,
                                    detected_at=time,
                                    attempted_event_id=event_id,
                                    severity="high",
                                    user_id=user_id,
                                    metadata={
                                        "prior_device": prev_dev,
                                        "current_device": device_id,
                                        "prior_ip": prev_ip,
                                        "current_ip": ip_hash,
                                        "time_delta_seconds": dt_sec,
                                        "prior_event_id": prev.get("event_id"),
                                    }
                                )
                                if not detected_violation:
                                    detected_violation = det
                                break
                            else:
                                # Same device and same IP: legitimate parallel requests from same client session
                                pass

        # Rule E: Impossible-travel detection (intercontinental or distant country switch in <= 300s)
        if country and dt_event and event_type in ("token_used", "token_refreshed", "login", "token_issued", "suspicious_location"):
            travel_history = (
                self._user_usages.get(user_id, [])
                if user_id != "unknown"
                else self._token_usages.get(token_hash, [])
            )
            for prev in reversed(travel_history):
                if prev["event_id"] == event_id:
                    continue
                prev_country = prev.get("country")
                if prev_country and prev_country != country:
                    dt_prev = prev.get("datetime")
                    if dt_prev:
                        dt_sec = abs((dt_event - dt_prev).total_seconds())
                        if dt_sec <= 300:  # <= 5 minutes
                            fam = (target_record.token_family if target_record else event_token_family) or f"family-{uuid.uuid4().hex[:8]}"
                            det = self._record_detection(
                                detection_type="impossible_travel",
                                token_hash=token_hash,
                                token_family=fam,
                                detected_at=time,
                                attempted_event_id=event_id,
                                severity="high",
                                user_id=user_id,
                                metadata={
                                    "origin_country": prev_country,
                                    "dest_country": country,
                                    "time_delta_seconds": dt_sec,
                                    "prior_event_id": prev.get("event_id"),
                                }
                            )
                            if not detected_violation:
                                detected_violation = det
                            break

        # Record usage history (idempotently per event_id)
        if dt_event:
            usage_entry = {
                "event_id": event_id,
                "time": time,
                "datetime": dt_event,
                "device_id": device_id,
                "ip_hash": ip_hash,
                "country": country,
            }
            if token_hash not in self._token_usages:
                self._token_usages[token_hash] = []
            if not any(u["event_id"] == event_id for u in self._token_usages[token_hash]):
                self._token_usages[token_hash].append(usage_entry)

            if user_id and user_id != "unknown":
                if user_id not in self._user_usages:
                    self._user_usages[user_id] = []
                if not any(u["event_id"] == event_id for u in self._user_usages[user_id]):
                    self._user_usages[user_id].append(usage_entry)

        # ---------------------------------------------------------
        # 3. TOKEN LIFECYCLE STATE MACHINE TRANSITIONS
        # ---------------------------------------------------------
        if event_type == "token_refreshed" and parent_token_hash:
            # Resolve parent token
            if parent_token_hash in self.tokens:
                parent = self.tokens[parent_token_hash]
                family_id = parent.token_family
                parent.status = TokenStatus.ROTATED
                if not parent.rotated_at:
                    parent.rotated_at = time
                if not parent.superseded_by:
                    parent.superseded_by = token_hash
            else:
                # Parent was not observed earlier; provisionally register it as rotated
                family_id = event_token_family or f"family-{uuid.uuid4().hex[:8]}"
                parent = TokenRecord(
                    token_hash=parent_token_hash,
                    token_family=family_id,
                    parent_token_hash=None,
                    status=TokenStatus.ROTATED,
                    rotated_at=time,
                    superseded_by=token_hash,
                    user_id=user_id,
                    session_id=device_id
                )
                self._register_token(parent)

            # Create or update child token
            if token_hash in self.tokens:
                child = self.tokens[token_hash]
                child.parent_token_hash = parent_token_hash
                child.token_family = family_id
                child.issued_at = child.issued_at or time
                child.user_id = user_id or child.user_id
                if child.status not in (TokenStatus.REVOKED, TokenStatus.EXPIRED, TokenStatus.ROTATED, TokenStatus.REUSED):
                    child.status = TokenStatus.ACTIVE
            else:
                child = TokenRecord(
                    token_hash=token_hash,
                    token_family=family_id,
                    parent_token_hash=parent_token_hash,
                    issued_at=time,
                    status=TokenStatus.ACTIVE,
                    user_id=user_id,
                    session_id=device_id
                )
                self._register_token(child)

        elif event_type == "token_issued":
            if token_hash not in self.tokens:
                family_id = event_token_family or f"family-{uuid.uuid4().hex[:8]}"
                token = TokenRecord(
                    token_hash=token_hash,
                    token_family=family_id,
                    parent_token_hash=parent_token_hash,
                    issued_at=time,
                    status=TokenStatus.ACTIVE,
                    user_id=user_id,
                    session_id=device_id
                )
                self._register_token(token)
            else:
                existing = self.tokens[token_hash]
                existing.issued_at = existing.issued_at or time
                if parent_token_hash and not existing.parent_token_hash:
                    existing.parent_token_hash = parent_token_hash
                if event_token_family and not existing.token_family:
                    existing.token_family = event_token_family
                # Never overwrite terminal or rotated lifecycle states with ACTIVE
                if existing.status not in (TokenStatus.REVOKED, TokenStatus.EXPIRED, TokenStatus.ROTATED, TokenStatus.REUSED):
                    existing.status = TokenStatus.ACTIVE

        elif event_type == "logout":
            # Explicit logout triggers family-level revocation
            family_to_revoke = event_token_family
            if token_hash in self.tokens:
                family_to_revoke = family_to_revoke or self.tokens[token_hash].token_family
                self.tokens[token_hash].status = TokenStatus.REVOKED
                self.tokens[token_hash].revoked_at = time
                self.tokens[token_hash].metadata["revoked_at"] = time
            elif token_hash:
                family_id = event_token_family or f"family-{uuid.uuid4().hex[:8]}"
                token = TokenRecord(
                    token_hash=token_hash,
                    token_family=family_id,
                    parent_token_hash=parent_token_hash,
                    issued_at=time,
                    status=TokenStatus.REVOKED,
                    revoked_at=time,
                    user_id=user_id,
                    session_id=device_id,
                    metadata={"revoked_at": time}
                )
                self._register_token(token)
                family_to_revoke = family_to_revoke or family_id

            if family_to_revoke and family_to_revoke in self.families:
                for th in self.families[family_to_revoke]:
                    if th in self.tokens:
                        self.tokens[th].status = TokenStatus.REVOKED
                        self.tokens[th].revoked_at = time
                        self.tokens[th].metadata["revoked_at"] = time

        elif event_type == "token_revoked":
            # Determine revocation scope: "family" or "token" (default)
            scope = event_data.get("revocation_scope") or event_data.get("metadata", {}).get("scope", "token")
            if scope == "family":
                family_to_revoke = event_token_family or (self.tokens[token_hash].token_family if token_hash in self.tokens else None)
                if token_hash in self.tokens:
                    self.tokens[token_hash].status = TokenStatus.REVOKED
                    self.tokens[token_hash].revoked_at = time
                    self.tokens[token_hash].metadata["revoked_at"] = time
                if family_to_revoke and family_to_revoke in self.families:
                    for th in self.families[family_to_revoke]:
                        if th in self.tokens:
                            self.tokens[th].status = TokenStatus.REVOKED
                            self.tokens[th].revoked_at = time
                            self.tokens[th].metadata["revoked_at"] = time
            else:
                # Token-level revocation: invalidate only this specific token
                if token_hash in self.tokens:
                    self.tokens[token_hash].status = TokenStatus.REVOKED
                    self.tokens[token_hash].revoked_at = time
                    self.tokens[token_hash].metadata["revoked_at"] = time
                elif token_hash:
                    family_id = event_token_family or f"family-{uuid.uuid4().hex[:8]}"
                    token = TokenRecord(
                        token_hash=token_hash,
                        token_family=family_id,
                        parent_token_hash=parent_token_hash,
                        issued_at=time,
                        status=TokenStatus.REVOKED,
                        revoked_at=time,
                        user_id=user_id,
                        session_id=device_id,
                        metadata={"revoked_at": time}
                    )
                    self._register_token(token)

        elif event_type == "token_expired":
            # Normal token expiration: sets status to EXPIRED; benign (zero alerts)
            if token_hash in self.tokens:
                self.tokens[token_hash].status = TokenStatus.EXPIRED
                self.tokens[token_hash].expired_at = time
                self.tokens[token_hash].metadata["expired_at"] = time
            elif token_hash:
                family_id = event_token_family or f"family-{uuid.uuid4().hex[:8]}"
                token = TokenRecord(
                    token_hash=token_hash,
                    token_family=family_id,
                    parent_token_hash=parent_token_hash,
                    issued_at=time,
                    status=TokenStatus.EXPIRED,
                    expired_at=time,
                    user_id=user_id,
                    session_id=device_id,
                    metadata={"expired_at": time}
                )
                self._register_token(token)

        # ---------------------------------------------------------
        # 4. Synchronize with database session if provided
        # ---------------------------------------------------------
        if db_session is not None:
            self._sync_db(event_data, db_session, detected_reuse, commit=commit)

        matching_alerts = [a for a in self.alerts if event_id in a.event_refs]
        return detected_reuse or (matching_alerts[0] if matching_alerts else None) or detected_violation

    def _register_token(self, token: TokenRecord):
        self.tokens[token.token_hash] = token
        if token.token_family not in self.families:
            self.families[token.token_family] = []
        if token.token_hash not in self.families[token.token_family]:
            self.families[token.token_family].append(token.token_hash)

    def reconstruct_chain(self, token_hash_or_family: str, db_session: Optional[Any] = None) -> List[str]:
        """
        Given a token_hash or token_family, returns the ordered chain A -> B -> C.
        Supports in-memory state with database session fallback.
        """
        # If DB session is provided, reconstruct directly from database records
        if db_session is not None:
            from backend.collector.db import TokenFamilyMember
            node = db_session.query(TokenFamilyMember).filter(TokenFamilyMember.token_hash == token_hash_or_family).first()
            if not node:
                node = db_session.query(TokenFamilyMember).filter(TokenFamilyMember.token_family == token_hash_or_family).first()
                if not node:
                    return []

            # Walk backward to find root
            root = node
            visited = set()
            while root.parent_token_hash and root.parent_token_hash not in visited:
                visited.add(root.token_hash)
                parent = db_session.query(TokenFamilyMember).filter(TokenFamilyMember.token_hash == root.parent_token_hash).first()
                if not parent:
                    break
                root = parent

            # Walk forward from root
            chain = []
            curr = root
            visited.clear()
            while curr and curr.token_hash not in visited:
                visited.add(curr.token_hash)
                chain.append(curr.token_hash)
                if not curr.superseded_by:
                    break
                curr = db_session.query(TokenFamilyMember).filter(TokenFamilyMember.token_hash == curr.superseded_by).first()

            return chain

        # Pure in-memory state reconstruction
        with self._lock:
            if token_hash_or_family in self.families:
                family_hashes = self.families[token_hash_or_family]
                if family_hashes:
                    root_hash = None
                    for th in family_hashes:
                        rec = self.tokens.get(th)
                        if rec and (not rec.parent_token_hash or rec.parent_token_hash not in self.tokens):
                            root_hash = th
                            break
                    if not root_hash:
                        root_hash = family_hashes[0]
                    return self._walk_forward_unlocked(root_hash)

            if token_hash_or_family in self.tokens:
                root_hash = self._find_root_unlocked(token_hash_or_family)
                return self._walk_forward_unlocked(root_hash)

            return []

    def _find_root_unlocked(self, token_hash: str) -> str:
        visited = set()
        curr = token_hash
        while curr in self.tokens and curr not in visited:
            visited.add(curr)
            parent = self.tokens[curr].parent_token_hash
            if not parent or parent not in self.tokens:
                return curr
            curr = parent
        return curr

    def _walk_forward_unlocked(self, root_hash: str) -> List[str]:
        chain = []
        visited = set()
        curr: Optional[str] = root_hash
        while curr and curr in self.tokens and curr not in visited:
            visited.add(curr)
            chain.append(curr)
            curr = self.tokens[curr].superseded_by
        return chain

    def get_ancestors(self, token_hash: str) -> List[str]:
        """
        Returns the ordered list of ancestor token hashes from root up to (excluding) token_hash.
        """
        with self._lock:
            if token_hash not in self.tokens:
                return []

            ancestors = []
            visited = {token_hash}
            curr = self.tokens[token_hash].parent_token_hash
            while curr and curr in self.tokens and curr not in visited:
                visited.add(curr)
                ancestors.insert(0, curr)
                curr = self.tokens[curr].parent_token_hash
            return ancestors

    def get_descendants(self, token_hash: str) -> List[str]:
        """
        Returns the ordered list of descendant token hashes from immediate child to leaf.
        """
        with self._lock:
            if token_hash not in self.tokens:
                return []

            descendants = []
            visited = {token_hash}
            curr = self.tokens[token_hash].superseded_by
            while curr and curr in self.tokens and curr not in visited:
                visited.add(curr)
                descendants.append(curr)
                curr = self.tokens[curr].superseded_by
            return descendants

    def get_family(self, token_family: str) -> List[TokenRecord]:
        """
        Returns all TokenRecord objects belonging to the specified family.
        """
        with self._lock:
            hashes = self.families.get(token_family, [])
            return [self.tokens[h] for h in hashes if h in self.tokens]

    def get_reuse_records(
        self,
        token_family: Optional[str] = None,
        token_hash: Optional[str] = None
    ) -> List[TokenReuseRecord]:
        """
        Returns recorded token reuse events, optionally filtered.
        """
        with self._lock:
            results = list(self.reuse_records)
            if token_family:
                results = [r for r in results if r.token_family == token_family]
            if token_hash:
                results = [r for r in results if r.token_hash == token_hash]
            return results

    def _sync_db(
        self,
        event_data: Dict[str, Any],
        db_session: Any,
        detected_reuse: Optional[TokenReuseRecord] = None,
        commit: bool = True
    ):
        """
        Synchronizes the current event and correlator state to the database idempotently.
        Uses nested savepoints when available to prevent race conditions on unique constraints.
        """
        try:
            from backend.collector.db import TokenFamilyMember, TokenReuseRecord as DBTokenReuseRecord
            from sqlalchemy.exc import IntegrityError

            event_id = event_data.get("event_id", "")
            event_type = event_data.get("event_type", "")
            time = event_data.get("time", "")
            user_id = event_data.get("user_id") or "unknown"
            token_hash = event_data.get("token_hash")
            parent_token_hash = event_data.get("parent_token_hash")
            event_token_family = event_data.get("token_family")

            # 1. Store reuse record if detected and not already present in DB
            if detected_reuse:
                existing_reuse = db_session.query(DBTokenReuseRecord).filter(
                    DBTokenReuseRecord.token_hash == detected_reuse.token_hash,
                    DBTokenReuseRecord.attempted_event_id == detected_reuse.attempted_event_id
                ).first()
                if not existing_reuse:
                    try:
                        if hasattr(db_session, "begin_nested"):
                            with db_session.begin_nested():
                                db_reuse = DBTokenReuseRecord(
                                    token_hash=detected_reuse.token_hash,
                                    token_family=detected_reuse.token_family,
                                    reused_at=detected_reuse.reused_at,
                                    attempted_event_id=detected_reuse.attempted_event_id
                                )
                                db_session.add(db_reuse)
                                db_session.flush()
                        else:
                            db_reuse = DBTokenReuseRecord(
                                token_hash=detected_reuse.token_hash,
                                token_family=detected_reuse.token_family,
                                reused_at=detected_reuse.reused_at,
                                attempted_event_id=detected_reuse.attempted_event_id
                            )
                            db_session.add(db_reuse)
                    except IntegrityError:
                        # Concurrently inserted in another transaction
                        pass

            # 2. Store standardized alerts if detected
            from backend.collector.db import Alert as DBAlert
            event_alerts = [a for a in self.alerts if event_id in a.event_refs]
            for alert in event_alerts:
                existing_alert = db_session.query(DBAlert).filter(
                    DBAlert.dedup_fingerprint == alert.dedup_fingerprint
                ).first()
                if not existing_alert:
                    try:
                        if hasattr(db_session, "begin_nested"):
                            with db_session.begin_nested():
                                db_alert = DBAlert(
                                    id=alert.id,
                                    rule_id=alert.rule_id,
                                    severity=alert.severity,
                                    status=alert.status,
                                    timestamp=alert.timestamp,
                                    title=alert.title,
                                    explanation=alert.explanation,
                                    event_refs_json=json.dumps(alert.event_refs),
                                    token_family_id=alert.token_family_id,
                                    token_hash=alert.token_hash,
                                    user_id=alert.user_id,
                                    evidence_json=json.dumps(alert.evidence),
                                    dedup_fingerprint=alert.dedup_fingerprint,
                                    created_at=alert.created_at,
                                    updated_at=alert.updated_at,
                                )
                                db_session.add(db_alert)
                                db_session.flush()
                        else:
                            db_alert = DBAlert(
                                id=alert.id,
                                rule_id=alert.rule_id,
                                severity=alert.severity,
                                status=alert.status,
                                timestamp=alert.timestamp,
                                title=alert.title,
                                explanation=alert.explanation,
                                event_refs_json=json.dumps(alert.event_refs),
                                token_family_id=alert.token_family_id,
                                token_hash=alert.token_hash,
                                user_id=alert.user_id,
                                evidence_json=json.dumps(alert.evidence),
                                dedup_fingerprint=alert.dedup_fingerprint,
                                created_at=alert.created_at,
                                updated_at=alert.updated_at,
                            )
                            db_session.add(db_alert)
                    except IntegrityError:
                        pass

            # 2. Sync token lifecycle records
            if event_type == "token_refreshed" and parent_token_hash:
                parent = db_session.query(TokenFamilyMember).filter(TokenFamilyMember.token_hash == parent_token_hash).first()
                if parent:
                    family_id = parent.token_family
                    parent.is_rotated = True
                    if not parent.rotated_at:
                        parent.rotated_at = time
                    if not parent.superseded_by:
                        parent.superseded_by = token_hash
                    db_session.add(parent)
                else:
                    family_id = event_token_family or f"family-{uuid.uuid4().hex[:8]}"
                    try:
                        if hasattr(db_session, "begin_nested"):
                            with db_session.begin_nested():
                                parent = TokenFamilyMember(
                                    token_hash=parent_token_hash,
                                    token_family=family_id,
                                    parent_token_hash=None,
                                    is_rotated=True,
                                    rotated_at=time,
                                    superseded_by=token_hash,
                                    user_id=user_id
                                )
                                db_session.add(parent)
                                db_session.flush()
                        else:
                            parent = TokenFamilyMember(
                                token_hash=parent_token_hash,
                                token_family=family_id,
                                parent_token_hash=None,
                                is_rotated=True,
                                rotated_at=time,
                                superseded_by=token_hash,
                                user_id=user_id
                            )
                            db_session.add(parent)
                    except IntegrityError:
                        parent = db_session.query(TokenFamilyMember).filter(TokenFamilyMember.token_hash == parent_token_hash).first()
                        if parent:
                            family_id = parent.token_family
                            parent.is_rotated = True
                            if not parent.rotated_at:
                                parent.rotated_at = time
                            if not parent.superseded_by:
                                parent.superseded_by = token_hash
                            db_session.add(parent)

                child = db_session.query(TokenFamilyMember).filter(TokenFamilyMember.token_hash == token_hash).first()
                if child:
                    child.parent_token_hash = parent_token_hash
                    child.token_family = family_id
                    db_session.add(child)
                else:
                    try:
                        if hasattr(db_session, "begin_nested"):
                            with db_session.begin_nested():
                                child = TokenFamilyMember(
                                    token_hash=token_hash,
                                    token_family=family_id,
                                    parent_token_hash=parent_token_hash,
                                    is_rotated=False,
                                    user_id=user_id
                                )
                                db_session.add(child)
                                db_session.flush()
                        else:
                            child = TokenFamilyMember(
                                token_hash=token_hash,
                                token_family=family_id,
                                parent_token_hash=parent_token_hash,
                                is_rotated=False,
                                user_id=user_id
                            )
                            db_session.add(child)
                    except IntegrityError:
                        child = db_session.query(TokenFamilyMember).filter(TokenFamilyMember.token_hash == token_hash).first()
                        if child:
                            child.parent_token_hash = parent_token_hash
                            child.token_family = family_id
                            db_session.add(child)

                if commit:
                    db_session.commit()
                else:
                    db_session.flush()

            elif event_type == "token_issued" and token_hash:
                token = db_session.query(TokenFamilyMember).filter(TokenFamilyMember.token_hash == token_hash).first()
                if not token:
                    family_id = event_token_family or f"family-{uuid.uuid4().hex[:8]}"
                    try:
                        if hasattr(db_session, "begin_nested"):
                            with db_session.begin_nested():
                                token = TokenFamilyMember(
                                    token_hash=token_hash,
                                    token_family=family_id,
                                    parent_token_hash=parent_token_hash,
                                    is_rotated=False,
                                    user_id=user_id
                                )
                                db_session.add(token)
                                db_session.flush()
                        else:
                            token = TokenFamilyMember(
                                token_hash=token_hash,
                                token_family=family_id,
                                parent_token_hash=parent_token_hash,
                                is_rotated=False,
                                user_id=user_id
                            )
                            db_session.add(token)
                    except IntegrityError:
                        pass

                if commit:
                    db_session.commit()
                else:
                    db_session.flush()

            elif detected_reuse or event_alerts:
                if commit:
                    db_session.commit()
                else:
                    db_session.flush()

        except Exception as e:
            if commit and hasattr(db_session, "rollback"):
                db_session.rollback()
            logger.error(
                f"Database synchronization failed during correlation for event {event_data.get('event_id')}: {e}",
                exc_info=True
            )
            raise


_default_correlator = TokenFamilyCorrelator()


@contextmanager
def correlator_transaction(correlator: Optional[TokenFamilyCorrelator] = None):
    """Context manager executing a correlator transaction on the default or specified engine."""
    c = correlator or _default_correlator
    with c.transaction():
        yield c


def process_event(
    event_data: Dict[str, Any],
    db_session: Optional[Any] = None,
    correlator: Optional[TokenFamilyCorrelator] = None,
    commit: Optional[bool] = None
) -> Optional[Any]:
    """Module-level helper delegating to the production TokenFamilyCorrelator."""
    c = correlator or _default_correlator
    return c.process_event(event_data, db_session=db_session, commit=commit)


def reconstruct_chain(
    token_hash_or_family: str,
    db_session: Optional[Any] = None,
    correlator: Optional[TokenFamilyCorrelator] = None
) -> List[str]:
    """Module-level helper delegating to the production TokenFamilyCorrelator."""
    c = correlator or _default_correlator
    return c.reconstruct_chain(token_hash_or_family, db_session=db_session)


def get_detection_records(
    detection_type: Optional[str] = None,
    token_family: Optional[str] = None,
    token_hash: Optional[str] = None,
    correlator: Optional[TokenFamilyCorrelator] = None,
) -> List[DetectionRecord]:
    """Module-level helper delegating to the production TokenFamilyCorrelator."""
    c = correlator or _default_correlator
    return c.get_detection_records(detection_type=detection_type, token_family=token_family, token_hash=token_hash)


def get_alerts(
    rule_id: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    token_family_id: Optional[str] = None,
    token_hash: Optional[str] = None,
    db_session: Optional[Any] = None,
    correlator: Optional[TokenFamilyCorrelator] = None,
) -> List[AlertRecord]:
    """Module-level helper delegating to the production TokenFamilyCorrelator."""
    c = correlator or _default_correlator
    return c.get_alerts(
        rule_id=rule_id,
        severity=severity,
        status=status,
        token_family_id=token_family_id,
        token_hash=token_hash,
        db_session=db_session,
    )


def update_alert_status(
    alert_id: str,
    new_status: str,
    db_session: Optional[Any] = None,
    commit: bool = True,
    correlator: Optional[TokenFamilyCorrelator] = None,
) -> Optional[AlertRecord]:
    """Module-level helper delegating to the production TokenFamilyCorrelator."""
    c = correlator or _default_correlator
    return c.update_alert_status(alert_id=alert_id, new_status=new_status, db_session=db_session, commit=commit)


def process_event_file(
    filepath: str,
    db_session: Optional[Any] = None,
    correlator: Optional[TokenFamilyCorrelator] = None
):
    """Processes all events in a JSON file through the production correlator."""
    import json
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        return

    with open(filepath, "r") as f:
        events = json.load(f)

    for event in events:
        process_event(event, db_session=db_session, correlator=correlator)
    print(f"Successfully processed {len(events)} events from {filepath}.")

