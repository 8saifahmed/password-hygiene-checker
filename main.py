"""Password Hygiene Checker - CLI entry point."""

import argparse
import getpass
import sys
from datetime import datetime

import db
import report
from hibp_client import PwnedStatus, check_password_pwned
from strength import analyze_strength


def _format_status(status: PwnedStatus, breach_count) -> tuple:
    """Render one history row's status and count columns.

    Handles every PwnedStatus explicitly; an unrecognised member raises rather
    than being displayed as a safe result.
    """
    if status is PwnedStatus.PWNED:
        return "yes", "{:,}".format(breach_count)
    if status is PwnedStatus.SAFE:
        return "no", "0"
    if status is PwnedStatus.LOOKUP_FAILED:
        return "unknown", "-"
    raise ValueError("unhandled PwnedStatus: {!r}".format(status))


def _print_history() -> int:
    """Print stored scan results. Returns a process exit code."""
    history = db.get_scan_history()
    if not history:
        print("No scans recorded yet. Run the tool without --history to add one.")
        return 0

    print("{:<4} {:<20} {:<10} {:>12}  {:<8} {}".format(
        "ID", "TIMESTAMP", "PWNED", "COUNT", "SCORE", "CRACK TIME"))
    print("-" * 78)
    for row in history:
        pwned, count = _format_status(row["pwned_status"], row["breach_count"])
        print("{:<4} {:<20} {:<10} {:>12}  {:<8} {}".format(
            row["id"],
            row["timestamp"],
            pwned,
            count,
            "{}/4".format(row["strength_score"]),
            row["crack_time_display"],
        ))
    print("-" * 78)
    print("{} scan(s) recorded. Passwords are never stored.".format(len(history)))
    return 0


def _run_scan() -> int:
    """Prompt for a password, report on it, and record the result."""
    password = getpass.getpass("Enter a password to check (input hidden): ")
    if not password:
        print("No password entered. Nothing to check.")
        return 1

    print("\nChecking against the Pwned Passwords database...")
    pwned_result = check_password_pwned(password)
    strength_result = analyze_strength(password)

    # Drop the password as soon as the analysis is done.
    del password

    print()
    print(report.build_report(pwned_result, strength_result))

    db.save_scan({
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "pwned_status": pwned_result.status,
        "breach_count": pwned_result.breach_count,
        "strength_score": strength_result["score"],
        "crack_time_display": strength_result["crack_time_display"],
    })
    print("\nResult saved to scan history (no password or hash was stored).")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="password-hygiene-checker",
        description="Check a password against known breaches and rate its strength.",
    )
    parser.add_argument(
        "--history",
        action="store_true",
        help="print past scan results instead of checking a new password",
    )
    args = parser.parse_args()

    try:
        db.init_db()
        if args.history:
            return _print_history()
        return _run_scan()
    except KeyboardInterrupt:
        print("\nCancelled.")
        return 130
    except EOFError:
        print("\nNo input received (is this running without a terminal?).")
        return 1
    except Exception as exc:  # noqa: BLE001 - CLI boundary: never show a traceback
        print("Error: {}: {}".format(type(exc).__name__, exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
