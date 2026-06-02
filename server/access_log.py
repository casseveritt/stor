"""Non-critical access logging for recipient and share-token asset fetches."""
import time
import uuid
from .db import now_ns


def log_access(db, asset_id: str, identity, endpoint: str) -> None:
    """Log a recipient or share-token access. Owner accesses are not logged."""
    if identity.is_owner:
        return
    try:
        db.execute(
            """INSERT INTO access_log
                 (id, asset_id, recipient_id, share_identity, endpoint, accessed_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                str(uuid.uuid4()),
                asset_id,
                identity.recipient_id,
                identity.share_identity if identity.is_share else None,
                endpoint,
                now_ns(),
            ),
        )
        db.commit()
    except Exception:
        pass
