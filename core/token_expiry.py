"""Local, unverified JWT expiry metadata; never a proof of token validity."""
import base64
import json
import math
from datetime import datetime, timezone


def access_token_expires_at(token):
    try:
        parts = str(token or "").strip().split(".")
        if len(parts) != 3 or len(parts[1]) > 65536:
            return None
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
        exp = payload.get("exp") if isinstance(payload, dict) else None
        if isinstance(exp, bool) or not isinstance(exp, (int, float)) or not math.isfinite(exp) or exp <= 0:
            return None
        return datetime.fromtimestamp(exp, timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, TypeError, OverflowError, OSError):
        return None
