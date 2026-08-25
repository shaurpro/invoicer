"""
IDOR (Insecure Direct Object Reference) Demo Application
----------------------------------------------------------
Educational project built for a security-lab assignment/viva.

This app is a tiny "Invoice Portal". Each user can log in and view
their own invoices at:

    /invoice/<invoice_id>

VULNERABILITY (on by default):
    The route fetches an invoice purely by its numeric ID and never
    checks whether the invoice actually belongs to the logged-in user.
    That means ANY logged-in user can view ANY other user's invoice
    just by changing the number in the URL -> classic IDOR.

FIX MODE:
    Set FIX_MODE = True below to switch on the corrected version of
    the same route, which adds the missing ownership check
    (WHERE id = ? AND user_id = ?). Use this to demonstrate the
    "before vs after" in your viva.

DO NOT deploy this app to the internet. It is intentionally insecure
for learning purposes only.
"""

from flask import Flask, request, redirect, url_for, session, render_template, abort
import sqlite3
import os

app = Flask(__name__)
app.secret_key = "demo-secret-key-not-for-production"

DB_PATH = os.path.join(os.path.dirname(__file__), "database.db")

# ----------------------------------------------------------------
# Flip this to True to demo the FIXED (secure) behaviour instead.
# ----------------------------------------------------------------
FIX_MODE = False


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.executescript("""
    DROP TABLE IF EXISTS users;
    DROP TABLE IF EXISTS invoices;

    CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    );

    CREATE TABLE invoices (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        amount TEXT NOT NULL,
        details TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """)

    # Demo users (plaintext passwords ONLY because this is a teaching demo)
    users = [
        (1, "alice", "alice123"),
        (2, "bob",   "bob123"),
        (3, "carol", "carol123"),
    ]
    cur.executemany("INSERT INTO users (id, username, password) VALUES (?, ?, ?)", users)

    invoices = [
        (101, 1, "Web Hosting - Alice",  "$120.00", "Alice's private billing address: 12 Rose St."),
        (102, 2, "Consulting - Bob",     "$980.00", "Bob's private billing address: 9 Pine Ave."),
        (103, 3, "Software License - Carol", "$450.00", "Carol's private billing address: 4 Oak Blvd."),
        (104, 1, "Domain Renewal - Alice", "$15.00", "Alice's card ending 4242"),
        (105, 2, "Server Upgrade - Bob",  "$300.00", "Bob's card ending 1234"),
    ]
    cur.executemany(
        "INSERT INTO invoices (id, user_id, title, amount, details) VALUES (?, ?, ?, ?, ?)",
        invoices
    )

    conn.commit()
    conn.close()


@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password)
        ).fetchone()
        conn.close()
        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))
        error = "Invalid username or password."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    my_invoices = conn.execute(
        "SELECT * FROM invoices WHERE user_id = ?", (session["user_id"],)
    ).fetchall()
    conn.close()
    return render_template(
        "dashboard.html",
        username=session["username"],
        invoices=my_invoices,
        fix_mode=FIX_MODE
    )


@app.route("/invoice/<int:invoice_id>")
def view_invoice(invoice_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()

    if FIX_MODE:
        # ---------------- SECURE VERSION ----------------
        # Ownership check added: the invoice must belong to
        # the currently logged-in user.
        invoice = conn.execute(
            "SELECT * FROM invoices WHERE id = ? AND user_id = ?",
            (invoice_id, session["user_id"])
        ).fetchone()
        conn.close()
        if invoice is None:
            abort(403)  # Forbidden - not your invoice
    else:
        # ---------------- VULNERABLE VERSION ----------------
        # IDOR: fetches by invoice_id only, no ownership check.
        # Any logged-in user can view ANY invoice by guessing/
        # incrementing the ID in the URL.
        invoice = conn.execute(
            "SELECT * FROM invoices WHERE id = ?", (invoice_id,)
        ).fetchone()
        conn.close()
        if invoice is None:
            abort(404)

    return render_template("invoice.html", invoice=invoice, fix_mode=FIX_MODE)


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        init_db()
    else:
        init_db()  # reset DB fresh on every run for a clean demo
    app.run(debug=True, host="0.0.0.0", port=5000)
