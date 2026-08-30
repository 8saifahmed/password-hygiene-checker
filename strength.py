"""Thin wrapper around zxcvbn that returns a stable, plain dictionary."""

from zxcvbn import zxcvbn

# zxcvbn's crack-time estimate under an offline attack on a slow hash. This is
# the most realistic of the four scenarios it reports for a leaked hash dump.
CRACK_TIME_KEY = "offline_slow_hashing_1e4_per_second"


def analyze_strength(password: str) -> dict:
    """Return zxcvbn's score, crack-time estimate, warning and suggestions."""
    if not isinstance(password, str) or not password:
        raise ValueError("password must be a non-empty string")

    result = zxcvbn(password)
    feedback = result.get("feedback") or {}

    return {
        "score": int(result.get("score", 0)),
        "crack_time_display": str(
            result.get("crack_times_display", {}).get(CRACK_TIME_KEY, "unknown")
        ),
        "warning": (feedback.get("warning") or "").strip(),
        "suggestions": [s for s in (feedback.get("suggestions") or []) if s],
    }
