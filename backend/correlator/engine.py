import uuid
from typing import Dict, List, Optional, Any, Union
from backend.correlator.models import TokenRecord, TokenReuseRecord, TokenStatus


class TokenFamilyCorrelator:
    """
    Token-Family Correlator
    Reconstructs refresh-token parent/child chains into token families,
    maintains rotation state, and flags refresh-token reuse without false alerting.
    """

    def __init__(self):
        # Key: token_hash -> TokenRecord
        self.tokens: Dict[str, TokenRecord] = {}
        # Key: token_family -> List[token_hash]
        self.families: Dict[str, List[str]] = {}
        # List of detected reuse occurrences
        self.reuse_records: List[TokenReuseRecord] = []

    def process_event(self, event_data: Dict[str, Any], db_session: Optional[Any] = None) -> Optional[TokenReuseRecord]:
        """
        Processes a schema-valid TokenLine authentication event.
        Updates internal token family state and flags reuse if detected.
        """
        event_id = event_data.get("event_id", "")
        event_type = event_data.get("event_type", "")
        time = event_data.get("time", "")
        user_id = event_data.get("user_id")
        token_hash = event_data.get("token_hash")
        parent_token_hash = event_data.get("parent_token_hash")
        event_token_family = event_data.get("token_family")
        device_id = event_data.get("device_id")
        ip_hash = event_data.get("ip_hash")

        if not token_hash:
            return None

        detected_reuse: Optional[TokenReuseRecord] = None

        # 1. Check for token reuse on rotated tokens
        # When refreshing, the client presents parent_token_hash.
        # When using/replaying, the client presents token_hash.
        target_check = parent_token_hash if (event_type == "token_refreshed" and parent_token_hash) else token_hash
        
        if target_check and target_check in self.tokens:
            target_record = self.tokens[target_check]
            if target_record.is_rotated:
                chain = self.reconstruct_chain(target_check)
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

        # 2. Handle token lifecycle events
        if event_type == "token_refreshed" and parent_token_hash:
            # Resolve parent family
            if parent_token_hash in self.tokens:
                parent = self.tokens[parent_token_hash]
                family_id = parent.token_family
                parent.status = TokenStatus.ROTATED
                parent.rotated_at = time
                parent.superseded_by = token_hash
            else:
                # Parent was not observed earlier; provisionally register it
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
                child.issued_at = time
                child.user_id = user_id or child.user_id
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

        elif event_type in ("logout", "token_revoked"):
            if token_hash in self.tokens:
                self.tokens[token_hash].status = TokenStatus.REVOKED
                self.tokens[token_hash].metadata["revoked_at"] = time

        elif event_type == "token_expired":
            if token_hash in self.tokens:
                self.tokens[token_hash].status = TokenStatus.EXPIRED

        # 3. Synchronize with optional SQLAlchemy database session if provided
        if db_session is not None:
            self._sync_with_db(event_data, db_session)

        return detected_reuse

    def _register_token(self, token: TokenRecord):
        self.tokens[token.token_hash] = token
        if token.token_family not in self.families:
            self.families[token.token_family] = []
        if token.token_hash not in self.families[token.token_family]:
            self.families[token.token_family].append(token.token_hash)

    def reconstruct_chain(self, token_hash_or_family: str) -> List[str]:
        """
        Given a token_hash or token_family, returns the ordered chain A -> B -> C.
        """
        # If input is a known family ID
        if token_hash_or_family in self.families:
            family_hashes = self.families[token_hash_or_family]
            if not family_hashes:
                return []
            # Find the root (node with no parent in family or parent not in family)
            root_hash = None
            for th in family_hashes:
                rec = self.tokens.get(th)
                if rec and (not rec.parent_token_hash or rec.parent_token_hash not in self.tokens):
                    root_hash = th
                    break
            if not root_hash:
                root_hash = family_hashes[0]
            return self._walk_forward(root_hash)

        # Otherwise treat as token_hash
        if token_hash_or_family not in self.tokens:
            return []

        # Find the root ancestor
        root_hash = self._find_root(token_hash_or_family)
        return self._walk_forward(root_hash)

    def _find_root(self, token_hash: str) -> str:
        visited = set()
        curr = token_hash
        while curr in self.tokens and curr not in visited:
            visited.add(curr)
            parent = self.tokens[curr].parent_token_hash
            if not parent or parent not in self.tokens:
                return curr
            curr = parent
        return curr

    def _walk_forward(self, root_hash: str) -> List[str]:
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
        results = self.reuse_records
        if token_family:
            results = [r for r in results if r.token_family == token_family]
        if token_hash:
            results = [r for r in results if r.token_hash == token_hash]
        return results

    def _sync_with_db(self, event_data: Dict[str, Any], db_session: Any):
        """
        Synchronizes with SQLAlchemy models (TokenFamilyMember, TokenReuseRecord)
        if an active DB session is supplied.
        """
        try:
            # Lazy import to avoid circular dependencies
            from backend.collector.db import TokenFamilyMember, TokenReuseRecord as DBTokenReuseRecord
            
            event_id = event_data.get("event_id")
            event_type = event_data.get("event_type")
            time = event_data.get("time")
            user_id = event_data.get("user_id")
            token_hash = event_data.get("token_hash")
            parent_token_hash = event_data.get("parent_token_hash")
            event_token_family = event_data.get("token_family")

            target_check = parent_token_hash if (event_type == "token_refreshed" and parent_token_hash) else token_hash
            if target_check:
                existing = db_session.query(TokenFamilyMember).filter(TokenFamilyMember.token_hash == target_check).first()
                if existing and existing.is_rotated:
                    db_reuse = DBTokenReuseRecord(
                        token_hash=target_check,
                        token_family=existing.token_family,
                        reused_at=time,
                        attempted_event_id=event_id
                    )
                    db_session.add(db_reuse)
                    db_session.commit()

            if event_type == "token_refreshed" and parent_token_hash:
                parent = db_session.query(TokenFamilyMember).filter(TokenFamilyMember.token_hash == parent_token_hash).first()
                if parent:
                    family_id = parent.token_family
                    parent.is_rotated = True
                    parent.rotated_at = time
                    parent.superseded_by = token_hash
                    db_session.add(parent)
                else:
                    family_id = event_token_family or f"family-{uuid.uuid4().hex[:8]}"
                    parent = TokenFamilyMember(
                        token_hash=parent_token_hash,
                        token_family=family_id,
                        parent_token_hash=None,
                        is_rotated=True,
                        rotated_at=time,
                        superseded_by=token_hash,
                        user_id=user_id or "unknown"
                    )
                    db_session.add(parent)

                child = db_session.query(TokenFamilyMember).filter(TokenFamilyMember.token_hash == token_hash).first()
                if child:
                    child.parent_token_hash = parent_token_hash
                    child.token_family = family_id
                    db_session.add(child)
                else:
                    child = TokenFamilyMember(
                        token_hash=token_hash,
                        token_family=family_id,
                        parent_token_hash=parent_token_hash,
                        is_rotated=False,
                        user_id=user_id or "unknown"
                    )
                    db_session.add(child)
                db_session.commit()

            elif event_type == "token_issued":
                token = db_session.query(TokenFamilyMember).filter(TokenFamilyMember.token_hash == token_hash).first()
                if not token:
                    family_id = event_token_family or f"family-{uuid.uuid4().hex[:8]}"
                    token = TokenFamilyMember(
                        token_hash=token_hash,
                        token_family=family_id,
                        parent_token_hash=parent_token_hash,
                        is_rotated=False,
                        user_id=user_id or "unknown"
                    )
                    db_session.add(token)
                    db_session.commit()
        except Exception:
            # Fallback gracefully if database models are not available in isolated test environments
            pass
