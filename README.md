# Password Hygiene Checker

A small command-line tool that tells you two independent things about a
password: whether it has already shown up in a public data breach, and how
hard it would be to guess.

## What it does

- Checks a password against the [Pwned Passwords](https://haveibeenpwned.com/Passwords)
  database of breached credentials and reports how many times it has appeared.
- Rates the password's strength with [zxcvbn](https://github.com/dropbox/zxcvbn),
  giving a 0–4 score, an estimated crack time, and concrete improvement tips.
- Prints a combined plain-text report.
- Records the *results* of every scan in a local SQLite database so you can
  review them later with `--history`.

The two signals are worth reading together. A password can be structurally
strong and still be worthless because it has already leaked — see the sample
output below, where a 4/4 "Strong" passphrase turns out to have appeared in
breaches over four thousand times.

## Why: the k-anonymity model

**Your password is never transmitted.** Not in full, not encrypted, not
hashed-and-sent. Here is exactly what happens when you run a check:

1. The password is hashed locally with SHA-1, producing a 40-character digest.
2. Only the **first 5 hex characters** of that digest are sent to
   `https://api.pwnedpasswords.com/range/{prefix}`.
3. The API responds with every breached hash suffix sharing that prefix —
   typically several hundred to a thousand of them.
4. Your password's remaining 35 characters are compared against that list
   **on your machine**.

The server therefore learns only that someone asked about one of roughly
half a million possible passwords sharing a prefix. It never learns which one,
and it never sees your password or its full hash. This is the k-anonymity
model, and it is why the API needs no authentication and no account.

Two further precautions:

- The raw password is never logged, printed, or written to disk.
- The SQLite database stores results only — pwned status, breach count,
  strength score, crack time. It contains no password and no hash of one.

Requests also send `Add-Padding: true`, so responses are padded to a uniform
size and the response length leaks nothing about your prefix.

## Setup

Requires Python 3.9 or newer.

```bash
cd password_checker
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

Check a password. The prompt is hidden — nothing is echoed to your terminal:

```bash
python main.py
```

Review past scans instead of running a new one:

```bash
python main.py --history
```

Run the test suite:

```bash
python test_manual.py
```

## Sample output

A real run against `correcthorsebatterystaple` — the famous XKCD passphrase,
which is strong by construction but has long since leaked:

```
Enter a password to check (input hidden):

Checking against the Pwned Passwords database...

==========================================================
PASSWORD HYGIENE REPORT
==========================================================

BREACH EXPOSURE
----------------------------------------------------------
  Status      : PWNED
  Appearances : 4,173 time(s) in known breaches
  Action      : Stop using this password everywhere.

STRENGTH
----------------------------------------------------------
  Score       : 4/4 (Strong)
  Crack time  : centuries
    (offline attack against a slow hash, 10k guesses/sec)

==========================================================

Result saved to scan history (no password or hash was stored).
```

And the scan history, including a row where the network was unavailable:

```
ID   TIMESTAMP            PWNED             COUNT  SCORE    CRACK TIME
------------------------------------------------------------------------------
3    2026-08-30T07:14:44  unknown               -  1/4      2 seconds
2    2026-08-30T07:14:35  yes               4,173  4/4      centuries
1    2026-08-30T07:04:41  yes          70,606,130  0/4      less than a second
------------------------------------------------------------------------------
3 scan(s) recorded. Passwords are never stored.
```

If the API is unreachable, the breach section reports `COULD NOT CHECK
(network/API error)` — explicitly distinct from a clean result — and the
strength analysis still runs. The tool degrades rather than failing.

## Lookup results

A lookup returns a `PwnedResult` — a frozen dataclass pairing a `PwnedStatus`
with a breach count:

| Status          | `breach_count` | Meaning                                  |
| --------------- | -------------- | ---------------------------------------- |
| `PWNED`         | `int >= 1`     | Found in breaches this many times        |
| `SAFE`          | `None`         | Not present in the database              |
| `LOOKUP_FAILED` | `None`         | The API could not be reached or parsed   |

The three states are distinct by construction. "Not breached" and "we could
not check" are different answers, and neither is ever encoded as a magic
number: `PwnedResult` rejects a `PWNED` result without a count, and any other
status carrying one. Consumers match on the status explicitly, so a status
nobody handled raises instead of being silently reported as safe.

The database mirrors this: `pwned_status` stores the status name
(`'PWNED'` / `'SAFE'` / `'LOOKUP_FAILED'`) and `breach_count` is `NULL` for
anything but a real breach, enforced by a table `CHECK` constraint.

**Upgrading from an older database.** Earlier versions stored `pwned_status`
as a boolean and encoded a failed lookup as `breach_count = -1`. There is no
automatic migration — this is a local cache with nothing irreplaceable in it.
Delete `password_checks.db` and it will be recreated on the next run. If you
forget, `init_db()` detects the old schema and tells you exactly that, rather
than misreading old sentinel rows as clean results.

## Project layout

```
password_checker/
├── main.py           CLI entry point and argument handling
├── hibp_client.py    Pwned Passwords k-anonymity lookups
├── strength.py       zxcvbn wrapper
├── report.py         Formats results as a terminal report
├── db.py             SQLite scan history
├── test_manual.py    Manual test pass
├── requirements.txt
├── .env.example      Template for the future breach-lookup key
└── .gitignore
```

## Roadmap

- **HIBP email breach lookup.** Check whether an *email address* appears in
  known breaches, and which ones, using the HIBP `breachedaccount` API. That
  endpoint — unlike the Pwned Passwords range API used here — requires a paid
  API key. `.env.example` already carries the `HIBP_API_KEY` placeholder for
  it; the key is not read or used by any current code path.
