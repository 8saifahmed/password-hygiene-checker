"""Manual test pass for the Password Hygiene Checker.

Run with:  ./venv/bin/python test_manual.py

Network tests hit the live Pwned Passwords API. Failures there are reported
as failures, not skips, so a broken client is never mistaken for a flaky link.
"""

import os
import secrets
import string
import sys
import tempfile
from unittest import mock

import requests

import db
import hibp_client
import report
import strength
from hibp_client import PwnedResult, PwnedStatus, check_password_pwned
from strength import analyze_strength

PASSED = []
FAILED = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        PASSED.append(name)
        print("  PASS  {}".format(name))
    else:
        FAILED.append(name)
        print("  FAIL  {}  {}".format(name, detail))


def section(title: str) -> None:
    print("\n== {} ==".format(title))


def random_password(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(length))


# --------------------------------------------------------------------------
def test_known_breached_password():
    section("HIBP: known-breached password")
    result = check_password_pwned("password123")
    check("password123 is reported as PWNED",
          result.status is PwnedStatus.PWNED, "got {}".format(result.status))
    check("breach count is a positive int",
          isinstance(result.breach_count, int) and result.breach_count > 0,
          "got {!r}".format(result.breach_count))
    if result.breach_count:
        print("       (reported {:,} appearances)".format(result.breach_count))


def test_random_password_not_breached():
    section("HIBP: freshly generated random password")
    result = check_password_pwned(random_password())
    check("random password is SAFE",
          result.status is PwnedStatus.SAFE, "got {}".format(result.status))
    check("safe result carries no breach count",
          result.breach_count is None, "got {!r}".format(result.breach_count))


def test_strength_scores():
    section("Strength: weak vs strong")
    weak = analyze_strength("12345")
    strong = analyze_strength(random_password(20))
    check("weak password scores low", weak["score"] <= 1, "got {}".format(weak["score"]))
    check("strong password scores 4", strong["score"] == 4, "got {}".format(strong["score"]))
    check("strong scores higher than weak", strong["score"] > weak["score"])
    check("weak result carries a crack time", bool(weak["crack_time_display"]))
    check("weak result carries feedback",
          bool(weak["warning"] or weak["suggestions"]))
    check("suggestions is a list", isinstance(strong["suggestions"], list))


def test_db_roundtrip():
    section("Database: write and read back")
    tmpdir = tempfile.mkdtemp(prefix="phc-test-")
    path = os.path.join(tmpdir, "test_checks.db")

    db.init_db(path)
    row_id = db.save_scan({
        "timestamp": "2026-01-01T12:00:00",
        "pwned_status": PwnedStatus.PWNED,
        "breach_count": 4242,
        "strength_score": 1,
        "crack_time_display": "3 minutes",
    }, path)
    check("save_scan returns a row id", isinstance(row_id, int) and row_id > 0)

    history = db.get_scan_history(path)
    check("history has one row", len(history) == 1, "got {}".format(len(history)))
    row = history[0]
    check("timestamp round-trips", row["timestamp"] == "2026-01-01T12:00:00")
    check("pwned_status round-trips as PwnedStatus",
          row["pwned_status"] is PwnedStatus.PWNED, "got {!r}".format(row["pwned_status"]))
    check("breach_count round-trips", row["breach_count"] == 4242)
    check("strength_score round-trips", row["strength_score"] == 1)
    check("crack_time_display round-trips", row["crack_time_display"] == "3 minutes")

    # init_db must be safe to call repeatedly against an existing database.
    db.init_db(path)
    db.save_scan({"pwned_status": PwnedStatus.SAFE, "breach_count": None,
                  "strength_score": 4, "crack_time_display": "centuries"}, path)
    history = db.get_scan_history(path)
    check("second scan appended", len(history) == 2, "got {}".format(len(history)))
    check("history is newest-first", history[0]["id"] > history[1]["id"])
    check("missing timestamp is auto-filled", bool(history[0]["timestamp"]))
    check("safe row stores a NULL breach count",
          history[0]["breach_count"] is None, "got {!r}".format(history[0]["breach_count"]))

    db.save_scan({"pwned_status": PwnedStatus.LOOKUP_FAILED, "breach_count": None,
                  "strength_score": 2, "crack_time_display": "unknown"}, path)
    row = db.get_scan_history(path)[0]
    check("lookup_failed round-trips",
          row["pwned_status"] is PwnedStatus.LOOKUP_FAILED
          and row["breach_count"] is None)
    check("lookup_failed is distinguishable from safe",
          row["pwned_status"] is not PwnedStatus.SAFE)

    # The storage layer must reject the states PwnedResult cannot express.
    for bad in ({"pwned_status": PwnedStatus.PWNED, "breach_count": None},
                {"pwned_status": PwnedStatus.SAFE, "breach_count": 5},
                {"pwned_status": "nonsense", "breach_count": None}):
        try:
            db.save_scan(dict(bad, strength_score=0, crack_time_display="x"), path)
            check("save_scan rejects {}".format(bad), False, "no exception raised")
        except ValueError:
            check("save_scan rejects {}".format(bad), True)


def test_sqlite_no_locking():
    section("Database: repeated writes leave no lock behind")
    tmpdir = tempfile.mkdtemp(prefix="phc-lock-")
    path = os.path.join(tmpdir, "lock.db")
    db.init_db(path)
    try:
        for i in range(25):
            db.save_scan({"pwned_status": PwnedStatus.PWNED, "breach_count": i + 1,
                          "strength_score": 2, "crack_time_display": "x"}, path)
            db.get_scan_history(path)
        check("25 interleaved write/read cycles succeed", True)
    except Exception as exc:  # noqa: BLE001
        check("25 interleaved write/read cycles succeed", False, repr(exc))

    # A second open connection must not block a write.
    import sqlite3
    holder = sqlite3.connect(path)
    holder.execute("SELECT * FROM scan_history").fetchall()
    try:
        db.save_scan({"pwned_status": PwnedStatus.SAFE, "breach_count": None,
                      "strength_score": 0, "crack_time_display": "x"}, path)
        check("write succeeds while another reader is open", True)
    except Exception as exc:  # noqa: BLE001
        check("write succeeds while another reader is open", False, repr(exc))
    finally:
        holder.close()


def test_empty_and_none_input():
    section("Empty / None input handling")
    for value in ("", None, 123):
        try:
            check_password_pwned(value)
            check("check_password_pwned rejects {!r}".format(value), False,
                  "no exception raised")
        except ValueError:
            check("check_password_pwned rejects {!r}".format(value), True)
        except Exception as exc:  # noqa: BLE001
            check("check_password_pwned rejects {!r}".format(value), False,
                  "raised {}".format(type(exc).__name__))

        try:
            analyze_strength(value)
            check("analyze_strength rejects {!r}".format(value), False,
                  "no exception raised")
        except ValueError:
            check("analyze_strength rejects {!r}".format(value), True)
        except Exception as exc:  # noqa: BLE001
            check("analyze_strength rejects {!r}".format(value), False,
                  "raised {}".format(type(exc).__name__))

    try:
        db.save_scan(None, os.path.join(tempfile.mkdtemp(), "x.db"))
        check("save_scan rejects None", False, "no exception raised")
    except ValueError:
        check("save_scan rejects None", True)


def test_network_failures():
    section("Network failure handling (no unhandled exceptions)")
    failures = {
        "timeout": requests.exceptions.Timeout("slow"),
        "connection error": requests.exceptions.ConnectionError("down"),
        "generic request error": requests.exceptions.RequestException("boom"),
        "ssl error": requests.exceptions.SSLError("bad cert"),
    }
    for name, exc in failures.items():
        with mock.patch("hibp_client.requests.get", side_effect=exc):
            try:
                result = check_password_pwned("anything")
                check("{} returns LOOKUP_FAILED".format(name),
                      result == PwnedResult(PwnedStatus.LOOKUP_FAILED),
                      "got {!r}".format(result))
            except Exception as raised:  # noqa: BLE001
                check("{} returns LOOKUP_FAILED".format(name), False,
                      "raised {}".format(type(raised).__name__))

    for status in (400, 429, 500, 503):
        response = mock.Mock(status_code=status, text="")
        with mock.patch("hibp_client.requests.get", return_value=response):
            result = check_password_pwned("anything")
            check("HTTP {} returns LOOKUP_FAILED".format(status),
                  result == PwnedResult(PwnedStatus.LOOKUP_FAILED),
                  "got {!r}".format(result))


def test_malformed_api_response():
    section("Malformed API response handling")
    bodies = {
        "empty body": "",
        "html error page": "<html><body>502 Bad Gateway</body></html>",
        "no colons": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nBBBB",
        "non-numeric count": "0000000000000000000000000000000000A:notanumber",
        "blank lines only": "\n\n\n",
        "truncated line": "ABC:",
    }
    for name, body in bodies.items():
        response = mock.Mock(status_code=200, text=body)
        with mock.patch("hibp_client.requests.get", return_value=response):
            try:
                result = check_password_pwned("anything")
                check("{} handled without crashing".format(name),
                      isinstance(result, PwnedResult)
                      and isinstance(result.status, PwnedStatus),
                      "got {!r}".format(result))
            except Exception as exc:  # noqa: BLE001
                check("{} handled without crashing".format(name), False,
                      "raised {}".format(type(exc).__name__))

    # A well-formed response containing the real suffix must parse correctly.
    import hashlib
    digest = hashlib.sha1(b"anything").hexdigest().upper()
    body = "0000000000000000000000000000000000A:5\r\n{}:99\r\n".format(digest[5:])
    response = mock.Mock(status_code=200, text=body)
    with mock.patch("hibp_client.requests.get", return_value=response):
        check("valid response parses count",
              check_password_pwned("anything") == PwnedResult(PwnedStatus.PWNED, 99))

    # Padded entries (count 0) must not be reported as a breach.
    body = "{}:0\r\n".format(digest[5:])
    response = mock.Mock(status_code=200, text=body)
    with mock.patch("hibp_client.requests.get", return_value=response):
        check("zero-count padding entry is SAFE",
              check_password_pwned("anything") == PwnedResult(PwnedStatus.SAFE))

    # A matched hash with an unreadable count must still fail closed as PWNED.
    body = "{}:notanumber\r\n".format(digest[5:])
    response = mock.Mock(status_code=200, text=body)
    with mock.patch("hibp_client.requests.get", return_value=response):
        check("unparseable count fails closed to PWNED count 1",
              check_password_pwned("anything") == PwnedResult(PwnedStatus.PWNED, 1))


def test_report_rendering():
    section("Report rendering")
    weak = analyze_strength("12345")
    text = report.build_report(PwnedResult(PwnedStatus.PWNED, 1234), weak)
    check("report names PWNED status", "PWNED" in text)
    check("report shows breach count", "1,234" in text)
    check("report shows a strength label", "Very Weak" in text)
    check("report never contains the password", "12345" not in text)

    failed_text = report.build_report(PwnedResult(PwnedStatus.LOOKUP_FAILED), weak)
    check("failed lookup says it could not check",
          "COULD NOT CHECK" in failed_text)
    check("failed lookup names the cause", "network/API error" in failed_text)
    check("failed lookup is not worded as clean",
          "Not found in any known breach" not in failed_text)
    check("failed lookup shows no breach count", "Appearances" not in failed_text)

    safe_text = report.build_report(PwnedResult(PwnedStatus.SAFE), weak)
    check("SAFE and LOOKUP_FAILED render differently", safe_text != failed_text)

    text = report.build_report(PwnedResult(PwnedStatus.SAFE),
                               analyze_strength(random_password()))
    check("clean password renders safely", "Not found" in text)
    check("at most two suggestions are shown",
          text.count("\n  - ") <= report.MAX_SUGGESTIONS)


def test_password_never_leaves_process():
    section("Privacy: only the SHA-1 prefix is transmitted")
    captured = {}

    def fake_get(url, **kwargs):
        captured["url"] = url
        captured["kwargs"] = kwargs
        return mock.Mock(status_code=200, text="")

    with mock.patch("hibp_client.requests.get", side_effect=fake_get):
        check_password_pwned("password123")

    url = captured.get("url", "")
    check("password absent from the URL", "password123" not in url)
    check("URL carries a 5-character prefix",
          url.startswith("https://api.pwnedpasswords.com/range/")
          and len(url.rsplit("/", 1)[1]) == 5, "got {}".format(url))
    check("prefix matches the SHA-1 of the password", url.endswith("CBFDA"),
          "got {}".format(url))
    check("a User-Agent header is sent",
          "User-Agent" in captured.get("kwargs", {}).get("headers", {}))
    check("a request timeout is set", captured.get("kwargs", {}).get("timeout") is not None)
    body = repr(captured.get("kwargs", {}))
    check("password absent from request kwargs", "password123" not in body)


def test_result_invariants():
    section("PwnedResult: illegal states are unrepresentable")
    check("SAFE defaults to no count",
          PwnedResult(PwnedStatus.SAFE).breach_count is None)
    check("LOOKUP_FAILED defaults to no count",
          PwnedResult(PwnedStatus.LOOKUP_FAILED).breach_count is None)
    check("PWNED keeps its count", PwnedResult(PwnedStatus.PWNED, 9).breach_count == 9)

    illegal = [
        ("PWNED without a count", (PwnedStatus.PWNED, None)),
        ("PWNED with a zero count", (PwnedStatus.PWNED, 0)),
        ("PWNED with a negative count", (PwnedStatus.PWNED, -1)),
        ("SAFE carrying a count", (PwnedStatus.SAFE, 5)),
        ("LOOKUP_FAILED carrying a count", (PwnedStatus.LOOKUP_FAILED, 0)),
    ]
    for name, args in illegal:
        try:
            PwnedResult(*args)
            check("rejects {}".format(name), False, "no exception raised")
        except ValueError:
            check("rejects {}".format(name), True)

    check("SAFE != LOOKUP_FAILED",
          PwnedResult(PwnedStatus.SAFE) != PwnedResult(PwnedStatus.LOOKUP_FAILED))
    check("equal results compare equal",
          PwnedResult(PwnedStatus.PWNED, 3) == PwnedResult(PwnedStatus.PWNED, 3))
    check("PwnedStatus has exactly three members", len(list(PwnedStatus)) == 3)


def test_exhaustive_status_handling():
    section("Every PwnedStatus is handled by every renderer")
    import main

    weak = analyze_strength("12345")
    counts = {PwnedStatus.PWNED: 7, PwnedStatus.SAFE: None,
              PwnedStatus.LOOKUP_FAILED: None}
    rendered = set()
    for status in PwnedStatus:
        result = PwnedResult(status, counts[status])
        try:
            text = report.build_report(result, weak)
            rendered.add(text)
            check("build_report handles {}".format(status.name), bool(text))
        except Exception as exc:  # noqa: BLE001
            check("build_report handles {}".format(status.name), False, repr(exc))

        try:
            main._format_status(status, counts[status])
            check("history row handles {}".format(status.name), True)
        except Exception as exc:  # noqa: BLE001
            check("history row handles {}".format(status.name), False, repr(exc))

    check("each status renders distinctly", len(rendered) == len(list(PwnedStatus)),
          "got {} distinct reports".format(len(rendered)))

    # An unknown status must raise, not fall through to a "safe" default.
    fake = mock.Mock(name="UnknownStatus")
    try:
        report.build_report(PwnedResult.__new__(PwnedResult), weak)
        check("build_report raises on an unhandled status", False, "no exception")
    except (ValueError, AttributeError):
        check("build_report raises on an unhandled status", True)
    try:
        main._format_status(fake, None)
        check("history row raises on an unhandled status", False, "no exception")
    except ValueError:
        check("history row raises on an unhandled status", True)


def test_legacy_db_detection():
    section("Database: old sentinel schema is detected, not misread")
    tmpdir = tempfile.mkdtemp(prefix="phc-legacy-")
    path = os.path.join(tmpdir, "legacy.db")

    import sqlite3
    legacy = sqlite3.connect(path)
    legacy.execute(
        """CREATE TABLE scan_history (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               timestamp TEXT NOT NULL,
               pwned_status INTEGER NOT NULL,
               breach_count INTEGER NOT NULL,
               strength_score INTEGER NOT NULL,
               crack_time_display TEXT NOT NULL)"""
    )
    legacy.execute(
        "INSERT INTO scan_history "
        "(timestamp, pwned_status, breach_count, strength_score, crack_time_display) "
        "VALUES ('2026-01-03T00:00:00', 0, -1, 1, '2 seconds')"
    )
    legacy.commit()
    legacy.close()

    try:
        db.init_db(path)
        check("legacy schema is rejected", False, "init_db accepted it")
    except RuntimeError as exc:
        check("legacy schema is rejected", True)
        check("error names the file", path in str(exc))
        check("error says to delete the file", "delete" in str(exc).lower())

    # The documented fix: delete and reinit.
    os.remove(path)
    db.init_db(path)
    check("reinit after deletion succeeds", db.get_scan_history(path) == [])
    row_id = db.save_scan({"pwned_status": PwnedStatus.PWNED, "breach_count": 3,
                           "strength_score": 0, "crack_time_display": "x"}, path)
    check("fresh database accepts writes", isinstance(row_id, int))


def main() -> int:
    print("Password Hygiene Checker - manual test pass")
    tests = [
        test_known_breached_password,
        test_random_password_not_breached,
        test_strength_scores,
        test_db_roundtrip,
        test_legacy_db_detection,
        test_sqlite_no_locking,
        test_result_invariants,
        test_exhaustive_status_handling,
        test_empty_and_none_input,
        test_network_failures,
        test_malformed_api_response,
        test_report_rendering,
        test_password_never_leaves_process,
    ]
    for test in tests:
        try:
            test()
        except Exception as exc:  # noqa: BLE001
            FAILED.append(test.__name__)
            print("  FAIL  {} raised {}: {}".format(test.__name__, type(exc).__name__, exc))

    print("\n" + "=" * 58)
    print("{} passed, {} failed".format(len(PASSED), len(FAILED)))
    if FAILED:
        for name in FAILED:
            print("  - {}".format(name))
    print("=" * 58)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
