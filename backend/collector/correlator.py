import uuid
import json
import os
from sqlalchemy.orm import Session
from db import get_session, TokenFamilyMember, TokenReuseRecord

def process_event(event_data: dict, db: Session):
    event_id = event_data.get("event_id")
    event_type = event_data.get("event_type")
    time = event_data.get("time")
    user_id = event_data.get("user_id")
    token_hash = event_data.get("token_hash")
    parent_token_hash = event_data.get("parent_token_hash")
    event_token_family = event_data.get("token_family")

    if not token_hash:
        return

    # Check for reuse on the presented token
    # For token_refreshed, the user presents the parent_token_hash.
    # For token_used, the user presents token_hash.
    target_check = parent_token_hash if event_type == "token_refreshed" else token_hash
    if target_check:
        existing = db.query(TokenFamilyMember).filter(TokenFamilyMember.token_hash == target_check).first()
        if existing and existing.is_rotated:
            # Reuse detected! Log condition in token_reuse_records
            reuse_record = TokenReuseRecord(
                token_hash=target_check,
                token_family=existing.token_family,
                reused_at=time,
                attempted_event_id=event_id
            )
            db.add(reuse_record)
            db.commit()

    if event_type == "token_refreshed" and parent_token_hash:
        # Resolve parent
        parent = db.query(TokenFamilyMember).filter(TokenFamilyMember.token_hash == parent_token_hash).first()
        if parent:
            family_id = parent.token_family
            # Mark parent as rotated
            if not parent.is_rotated:
                parent.is_rotated = True
                parent.rotated_at = time
                parent.superseded_by = token_hash
                db.add(parent)
        else:
            # Parent not seen before. Create a root for it provisionally.
            family_id = event_token_family or f"family-{uuid.uuid4().hex[:8]}"
            parent = TokenFamilyMember(
                token_hash=parent_token_hash,
                token_family=family_id,
                parent_token_hash=None,
                is_rotated=True,
                rotated_at=time,
                superseded_by=token_hash,
                user_id=user_id
            )
            db.add(parent)

        # Create or update child token
        child = db.query(TokenFamilyMember).filter(TokenFamilyMember.token_hash == token_hash).first()
        if child:
            child.parent_token_hash = parent_token_hash
            child.token_family = family_id
            db.add(child)
        else:
            child = TokenFamilyMember(
                token_hash=token_hash,
                token_family=family_id,
                parent_token_hash=parent_token_hash,
                is_rotated=False,
                user_id=user_id
            )
            db.add(child)
        db.commit()

    elif event_type == "token_issued":
        # Check if already registered
        token = db.query(TokenFamilyMember).filter(TokenFamilyMember.token_hash == token_hash).first()
        if not token:
            family_id = event_token_family or f"family-{uuid.uuid4().hex[:8]}"
            token = TokenFamilyMember(
                token_hash=token_hash,
                token_family=family_id,
                parent_token_hash=None,
                is_rotated=False,
                user_id=user_id
            )
            db.add(token)
            db.commit()

def reconstruct_chain(token_hash: str, db: Session) -> list:
    # Find the node
    node = db.query(TokenFamilyMember).filter(TokenFamilyMember.token_hash == token_hash).first()
    if not node:
        return []

    # Walk backward to find root
    root = node
    visited = set()
    while root.parent_token_hash and root.parent_token_hash not in visited:
        visited.add(root.token_hash)
        parent = db.query(TokenFamilyMember).filter(TokenFamilyMember.token_hash == root.parent_token_hash).first()
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
        curr = db.query(TokenFamilyMember).filter(TokenFamilyMember.token_hash == curr.superseded_by).first()

    return chain

def process_event_file(filepath: str):
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        return

    with open(filepath, "r") as f:
        events = json.load(f)

    db = get_session()
    try:
        for event in events:
            process_event(event, db)
        print(f"Successfully processed {len(events)} events from {filepath}.")
    finally:
        db.close()
