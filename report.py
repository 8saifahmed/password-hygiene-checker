"""Formats scan results as a plain-text terminal report."""

from hibp_client import PwnedResult, PwnedStatus

WIDTH = 58

SCORE_LABELS = {
    0: "Very Weak",
    1: "Weak",
    2: "Fair",
    3: "Good",
    4: "Strong",
}

MAX_SUGGESTIONS = 2


def _header(title: str) -> str:
    return "{}\n{}".format(title, "-" * WIDTH)


def _breach_lines(pwned_result: PwnedResult) -> list:
    """Render the breach section, handling every PwnedStatus explicitly.

    Every member of PwnedStatus is matched by name. A new member added later
    falls through to the final raise rather than being absorbed by a default
    branch, so the omission surfaces immediately instead of being reported as
    a clean bill of health.
    """
    status = pwned_result.status

    if status is PwnedStatus.PWNED:
        return [
            "  Status      : PWNED",
            "  Appearances : {:,} time(s) in known breaches".format(
                pwned_result.breach_count
            ),
            "  Action      : Stop using this password everywhere.",
        ]

    if status is PwnedStatus.SAFE:
        return ["  Status      : Not found in any known breach"]

    if status is PwnedStatus.LOOKUP_FAILED:
        return [
            "  Status      : COULD NOT CHECK (network/API error)",
            "  Note        : Breach status is unknown - this is NOT a clean",
            "                result. Strength results below are still valid.",
        ]

    raise ValueError("unhandled PwnedStatus: {!r}".format(status))


def build_report(pwned_result: PwnedResult, strength_result: dict) -> str:
    """Combine a PwnedResult and an analyze_strength dict into a report."""
    score = strength_result.get("score", 0)
    label = SCORE_LABELS.get(score, "Unknown")

    lines = ["=" * WIDTH, "PASSWORD HYGIENE REPORT", "=" * WIDTH, ""]

    lines.append(_header("BREACH EXPOSURE"))
    lines.extend(_breach_lines(pwned_result))
    lines.append("")

    lines.append(_header("STRENGTH"))
    lines.append("  Score       : {}/4 ({})".format(score, label))
    lines.append("  Crack time  : {}".format(strength_result.get("crack_time_display", "unknown")))
    lines.append("    (offline attack against a slow hash, 10k guesses/sec)")
    lines.append("")

    warning = strength_result.get("warning", "")
    suggestions = strength_result.get("suggestions", [])[:MAX_SUGGESTIONS]

    if warning or suggestions:
        lines.append(_header("SUGGESTIONS"))
        if warning:
            lines.append("  ! {}".format(warning))
        for suggestion in suggestions:
            lines.append("  - {}".format(suggestion))
        lines.append("")

    lines.append("=" * WIDTH)
    return "\n".join(lines)
