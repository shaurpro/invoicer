# IDOR (Insecure Direct Object Reference) Demo — Invoice Portal

A tiny Flask + SQLite web app built as a security-lab assignment to demonstrate
**IDOR (Insecure Direct Object Reference / OWASP: Broken Access Control)**.

## What is IDOR?

IDOR happens when an application lets a user access a specific object (an
invoice, a file, a profile, an order) by referencing it directly — usually a
plain numeric ID in a URL or API call — **without verifying that the currently
authenticated user is actually authorized to view that particular object.**

The app correctly checks that *someone* is logged in, but never checks that
the record being requested actually **belongs** to that someone. Because the
authentication check "looks" complete, this is one of the easiest access
control bugs to accidentally ship.

**Typical exploitation flow:**
1. Attacker logs in as a normal user.
2. They see their own object ID somewhere legitimate (e.g. `/invoice/101`).
3. They change the ID (`/invoice/102`, `/invoice/103`, ...) or tamper with a
   hidden parameter.
4. If there's no ownership check server-side, the app returns another user's
   private data.

## This App

A minimal "Invoice Portal":

- 3 demo users: `alice`, `bob`, `carol`
- Each user has their own invoices in the database
- Route: `GET /invoice/<invoice_id>` — shows invoice details

### The vulnerability (default mode)

```python
# app.py -> view_invoice()
invoice = conn.execute(
    "SELECT * FROM invoices WHERE id = ?", (invoice_id,)
).fetchone()
```

The query fetches an invoice by ID only. There's no `AND user_id = ?`
clause, so **any logged-in user can view any other user's invoice** just by
changing the number in the URL.

### The fix (toggle-able)

Set `FIX_MODE = True` at the top of `app.py` to switch to the corrected
query used in the same route:

```python
invoice = conn.execute(
    "SELECT * FROM invoices WHERE id = ? AND user_id = ?",
    (invoice_id, session["user_id"])
).fetchone()
if invoice is None:
    abort(403)
```

This adds the missing **object-level authorization check**: the invoice must
belong to the session's logged-in user, or the server returns `403
Forbidden` instead of the data.

## Setup & Run

```bash
git clone <this-repo-url>
cd idor-demo
pip install flask
python3 app.py
```

The app runs at `http://127.0.0.1:5000` and resets/reseeds the SQLite
database (`database.db`) every time it starts, so the demo is always in a
clean state.

### Demo accounts

| Username | Password  | Owns invoices |
|----------|-----------|----------------|
| alice    | alice123  | 101, 104       |
| bob      | bob123    | 102, 105       |
| carol    | carol123  | 103            |

## Demonstrating the Attack (for viva)

1. Start the app (`python3 app.py`), confirm `FIX_MODE = False` in `app.py`.
2. Open `http://127.0.0.1:5000` and log in as **alice / alice123**.
3. On the dashboard, click "View" on your own invoice — note the URL is
   `/invoice/101`.
4. Manually edit the browser URL to `/invoice/102` (Bob's invoice) or
   `/invoice/103` (Carol's invoice).
5. **Result:** Alice, while logged in as herself, sees Bob's/Carol's private
   billing details — the IDOR. No error, no permission check.
6. (Optional) Repeat using `curl`/Postman/Burp Suite to show it isn't just a
   UI issue — the API-level endpoint itself is unprotected:
   ```bash
   curl -c cookies.txt -X POST http://127.0.0.1:5000/login \
        -d "username=alice&password=alice123"
   curl -b cookies.txt http://127.0.0.1:5000/invoice/102
   ```

## Demonstrating the Fix

1. Stop the app. Open `app.py` and set `FIX_MODE = True`.
2. Restart (`python3 app.py`).
3. Repeat the same steps: log in as alice, try `/invoice/102`.
4. **Result:** the server now returns `403 Forbidden` instead of Bob's data,
   because the query checks `user_id = session["user_id"]` before returning
   any row.

## Why this matters (real-world impact)

IDOR is consistently in OWASP's Top 10 (under **Broken Access Control**) and
has caused real breaches — exposed medical records, leaked financial
statements, account takeovers — because the fix is often a single missing
`WHERE` clause. Testing for it is simple (increment an ID), but it's easy for
developers to miss because authentication and authorization are two
different checks, and only the first one is obvious from the code.

## Disclaimer

This application is **intentionally vulnerable** and built strictly for
educational/lab purposes. Do not deploy it to a public server or use these
patterns in production code.
