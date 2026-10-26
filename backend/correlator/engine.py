import uuid
import os
import logging
import threading
import copy
from contextlib import contextmanager
from typing import Dict, List, Optional, Any, Set, Tuple
from backend.correlator.models import TokenRecord, TokenReuseRecord, TokenStatus

logger = logging.getLogger("tokenline.correlator.engine")

_transaction_context = threading.local()


def is_in_transaction() -> bool:
    """Returns True if the current thread is within an active correlator transaction."""
    return getattr(_transaction_context, "active", False)


class TokenFamilyCorrelator:
    """
    Unified Token-Family Correlator & State-Machine Engine.
    Reconstructs refresh-token parent/child chains into token families,
    maintains lifecycle states (ACTIVE, ROTATED, REVOKED, EXPIRED),
    and flags refresh-token reuse.
    Provides idempotent, thread-safe correlation across concurrent and replayed events.
    """

    def __init__(self):
        self._lock = threading.RLock()
        # Key: token_hash -> TokenRecord
        self.tokens: Dict[str, TokenRecord] = {}
        # Key: token_family -> List[token_hash]
        self.families: Dict[str, List[str]] = {}
        # List of detected reuse occurrences
        self.reuse_records: List[TokenReuseRecord] = []
        # Set of (token_hash, attempted_event_id) pairs to guarantee idempotent reuse recording
        self._reuse_seen: Set[Tuple[str, str]] = set()

    def clear(self):
        """Clears in-memory correlation state thread-safely."""
        with self._lock:
            self.tokens.clear()
            self.families.clear()
            self.reuse_records.clear()
            self._reuse_seen.clear()

    def _snapshot(self) -> Dict[str, Any]:
        """Captures a deep copy of all in-memory correlation state."""
        return {
            "tokens": copy.deepcopy(self.tokens),
            "families": copy.deepcopy(self.families),
            "reuse_records": copy.deepcopy(self.reuse_records),
            "_reuse_seen": copy.copy(self._reuse_seen),
        }

    def _restore(self, snap: Dict[str, Any]):
        """Restores in-memory correlation state from a snapshot."""
        self.tokens = snap["tokens"]
        self.families = snap["families"]
        self.reuse_records = snap["reuse_records"]
        self._reuse_seen = snap["_reuse_seen"]

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
    ) -> Optional[TokenReuseRecord]:
        """
        Processes a schema-valid TokenLine authentication event idempotently.
        Updates internal token family state machine and flags reuse if detected.
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
    ) -> Optional[TokenReuseRecord]:
        event_id = event_data.get("event_id", "")
        event_type = event_data.get("event_type", "")
        time = event_data.get("time", "")
        user_id = event_data.get("user_id") or "unknown"
        token_hash = event_data.get("token_hash")
        parent_token_hash = event_data.get("parent_token_hash")
        event_token_family = event_data.get("token_family")
        device_id = event_data.get("device_id")
        ip_hash = event_data.get("ip_hash")

        if not token_hash:
            return None

        detected_reuse: Optional[TokenReuseRecord] = None

        # 1. Check for token reuse on rotated tokens
        # When refreshing, client presents parent_token_hash.
        # When using/replaying, client presents token_hash.
        target_check = None
        if event_type == "token_refreshed" and parent_token_hash:
            target_check = parent_token_hash
        elif event_type not in ("token_issued", "logout", "token_revoked", "token_expired"):
            target_check = token_hash

        if target_check:
            if db_session is not None:
                from backend.collector.db import TokenFamilyMember as DBTokenFamilyMember, TokenReuseRecord as DBTokenReuseRecord
                existing_db = db_session.query(DBTokenFamilyMember).filter(DBTokenFamilyMember.token_hash == target_check).first()
                if existing_db and existing_db.is_rotated:
                    # If this is the legitimate rotation being replayed, it is NOT a new reuse attack.
                    if event_type == "token_refreshed" and existing_db.superseded_by == token_hash:
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
                                    "endpoint": event_data.get("endpoint"),
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
                                    "endpoint": event_data.get("endpoint"),
                                }
                            )
                        if reuse_key not in self._reuse_seen:
                            self.reuse_records.append(detected_reuse)
                            self._reuse_seen.add(reuse_key)
            elif target_check in self.tokens:
                target_record = self.tokens[target_check]
                if target_record.is_rotated:
                    # Legitimate rotation replay check
                    if event_type == "token_refreshed" and target_record.superseded_by == token_hash:
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
                                    "endpoint": event_data.get("endpoint"),
                                }
                            )
                            self.reuse_records.append(detected_reuse)
                            self._reuse_seen.add(reuse_key)

        # 2. Handle token lifecycle state machine transitions
        if event_type == "token_refreshed" and parent_token_hash:
            # Resolve parent
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
                if child.status not in (TokenStatus.REVOKED, TokenStatus.EXPIRED):
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
                if existing.status not in (TokenStatus.REVOKED, TokenStatus.EXPIRED, TokenStatus.ROTATED):
                    existing.status = TokenStatus.ACTIVE

        elif event_type == "logout":
            # Logout revokes the token and the entire associated token family
            family_to_revoke = event_token_family
            if token_hash in self.tokens:
                family_to_revoke = family_to_revoke or self.tokens[token_hash].token_family
                self.tokens[token_hash].status = TokenStatus.REVOKED
                self.tokens[token_hash].metadata["revoked_at"] = time
            elif token_hash:
                family_id = event_token_family or f"family-{uuid.uuid4().hex[:8]}"
                token = TokenRecord(
                    token_hash=token_hash,
                    token_family=family_id,
                    parent_token_hash=parent_token_hash,
                    issued_at=time,
                    status=TokenStatus.REVOKED,
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
                        self.tokens[th].metadata["revoked_at"] = time

        elif event_type == "token_revoked":
            family_to_revoke = event_token_family
            if token_hash in self.tokens:
                family_to_revoke = family_to_revoke or self.tokens[token_hash].token_family
                self.tokens[token_hash].status = TokenStatus.REVOKED
                self.tokens[token_hash].metadata["revoked_at"] = time
            elif token_hash:
                family_id = event_token_family or f"family-{uuid.uuid4().hex[:8]}"
                token = TokenRecord(
                    token_hash=token_hash,
                    token_family=family_id,
                    parent_token_hash=parent_token_hash,
                    issued_at=time,
                    status=TokenStatus.REVOKED,
                    user_id=user_id,
                    session_id=device_id,
                    metadata={"revoked_at": time}
                )
                self._register_token(token)
                family_to_revoke = family_to_revoke or family_id

            if event_token_family and event_token_family in self.families:
                for th in self.families[event_token_family]:
                    if th in self.tokens:
                        self.tokens[th].status = TokenStatus.REVOKED
                        self.tokens[th].metadata["revoked_at"] = time

        elif event_type == "token_expired":
            if token_hash in self.tokens:
                self.tokens[token_hash].status = TokenStatus.EXPIRED
                self.tokens[token_hash].metadata["expired_at"] = time
            elif token_hash:
                family_id = event_token_family or f"family-{uuid.uuid4().hex[:8]}"
                token = TokenRecord(
                    token_hash=token_hash,
                    token_family=family_id,
                    parent_token_hash=parent_token_hash,
                    issued_at=time,
                    status=TokenStatus.EXPIRED,
                    user_id=user_id,
                    session_id=device_id,
                    metadata={"expired_at": time}
                )
                self._register_token(token)

        # 3. Synchronize with database session if provided
        if db_session is not None:
            self._sync_db(event_data, db_session, detected_reuse, commit=commit)

        return detected_reuse

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

            elif detected_reuse:
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
) -> Optional[TokenReuseRecord]:
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

