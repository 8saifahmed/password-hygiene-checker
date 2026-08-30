"""Pwned Passwords lookups using the k-anonymity range API.

The full password never leaves this process: only the first five hex
characters of its SHA-1 digest are sent to the API, and the suffix
comparison happens locally.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum

import requests

API_URL = "https://api.pwnedpasswords.com/range/{prefix}"
USER_AGENT = "password-hygiene-checker/1.0 (python; educational CLI tool)"
REQUEST_TIMEOUT = 10  # seconds


class PwnedStatus(Enum):
    """Outcome of a Pwned Passwords lookup."""

    PWNED = "PWNED"
    SAFE = "SAFE"
    LOOKUP_FAILED = "LOOKUP_FAILED"


@dataclass(frozen=True)
class PwnedResult:
    """Result of a breach lookup.

    `breach_count` is an int only when `status` is PWNED; it is None for both
    SAFE and LOOKUP_FAILED, so "not breached" and "we could not tell" are
    never confused with each other or with a count.
    """

    status: PwnedStatus
    breach_count: int | None = None

    def __post_init__(self) -> None:
        if self.status is PwnedStatus.PWNED:
            if not isinstance(self.breach_count, int) or self.breach_count < 1:
                raise ValueError("PWNED results require a positive breach_count")
        elif self.breach_count is not None:
            raise ValueError(
                "breach_count must be None unless status is PWNED"
            )


def check_password_pwned(password: str) -> PwnedResult:
    """Look `password` up in the Pwned Passwords database.

    Never raises on network trouble: any failure returns a LOOKUP_FAILED
    result so the caller can still report strength results.
    """
    if not isinstance(password, str) or not password:
        raise ValueError("password must be a non-empty string")

    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]

    try:
        response = requests.get(
            API_URL.format(prefix=prefix),
            headers={"User-Agent": USER_AGENT, "Add-Padding": "true"},
            timeout=REQUEST_TIMEOUT,
        )
    except requests.exceptions.Timeout:
        print("  [!] Pwned Passwords lookup timed out.")
        return PwnedResult(PwnedStatus.LOOKUP_FAILED)
    except requests.exceptions.ConnectionError:
        print("  [!] Could not reach the Pwned Passwords API (no connection).")
        return PwnedResult(PwnedStatus.LOOKUP_FAILED)
    except requests.exceptions.RequestException as exc:
        print("  [!] Pwned Passwords lookup failed: {}".format(type(exc).__name__))
        return PwnedResult(PwnedStatus.LOOKUP_FAILED)

    if response.status_code != 200:
        print(
            "  [!] Pwned Passwords API returned HTTP {}.".format(response.status_code)
        )
        return PwnedResult(PwnedStatus.LOOKUP_FAILED)

    return _parse_range_response(response.text, suffix)


def _parse_range_response(body: str, suffix: str) -> PwnedResult:
    """Scan a range-API response body for `suffix` and build a result.

    Malformed lines are skipped rather than treated as fatal: the API pads
    responses and a single bad row should not hide a real match.
    """
    for line in body.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        line_suffix, _, line_count = line.partition(":")
        if line_suffix.strip().upper() != suffix:
            continue

        try:
            count = int(line_count.strip())
        except ValueError:
            # The hash matched but the count is unreadable; the match itself is
            # the meaningful signal, so fail closed and report one exposure.
            return PwnedResult(PwnedStatus.PWNED, 1)

        if count < 1:
            # Padding entries carry a count of zero and are not real matches.
            return PwnedResult(PwnedStatus.SAFE)
        return PwnedResult(PwnedStatus.PWNED, count)

    return PwnedResult(PwnedStatus.SAFE)
