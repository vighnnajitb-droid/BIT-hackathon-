#!/usr/bin/env python3
"""
PyBank - Bank Management System Using Only Python
=================================================
* GUI      : Tkinter / ttk (standard library)
* Database : SQLite via the built-in sqlite3 module (file: bank.db, auto-created)
* Security : PINs / passwords stored as salted PBKDF2-HMAC-SHA256 hashes
* SQL      : parameterized queries only; fund transfers run in one DB transaction

Run:   python bank_system.py
Admin: username "admin"  /  password "admin@123"   (created on first run)
"""

import csv
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import tkinter as tk
from contextlib import contextmanager
from datetime import datetime
from decimal import Decimal, InvalidOperation
from tkinter import filedialog, messagebox, ttk

DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bank.db")
MIN_INITIAL_DEPOSIT = Decimal("500")
MAX_TXN_AMOUNT = Decimal("1000000")
DAILY_LIMIT = Decimal("200000")   # max total withdrawals + transfers out per account per day
MIN_BALANCE = Decimal("100")      # balance that must remain after a withdrawal / transfer
LOW_BALANCE_DEFAULT = 1000        # default threshold for the low-balance report
ORDERS = {"high": "a.balance DESC", "low": "a.balance ASC"}
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "transactions_log.csv")
CSV_HEADER = ["Transaction ID", "Date/Time", "Account", "Type", "Amount", "Description", "Related Account", "Balance After"]
ACCOUNT_TYPES = ("Savings", "Current")
CREDIT_TYPES = {"DEPOSIT", "TRANSFER_IN"}
TXN_TYPES = ("DEPOSIT", "WITHDRAWAL", "TRANSFER_OUT", "TRANSFER_IN")


# --------------------------------------------------------------------------
# Helpers: errors, hashing, formatting, validation
# --------------------------------------------------------------------------
class BankError(Exception):
    """Any business-rule or validation failure that should be shown to the user."""


class ValidationError(BankError):
    pass


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def hash_secret(secret, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), bytes.fromhex(salt), 200_000)
    return f"{salt}${digest.hex()}"


def verify_secret(secret, stored):
    try:
        salt, _ = stored.split("$", 1)
    except ValueError:
        return False
    return hmac.compare_digest(hash_secret(secret, salt), stored)


def inr(amount):
    """Format a number as Indian Rupees with lakh/crore grouping, e.g. ₹12,34,567.50"""
    d = Decimal(str(amount)).quantize(Decimal("0.01"))
    sign = "-" if d < 0 else ""
    whole, frac = f"{abs(d):.2f}".split(".")
    if len(whole) > 3:
        head, tail = whole[:-3], whole[-3:]
        parts = []
        while len(head) > 2:
            parts.insert(0, head[-2:])
            head = head[:-2]
        if head:
            parts.insert(0, head)
        whole = ",".join(parts + [tail])
    return f"{sign}\u20b9{whole}.{frac}"


def parse_amount(text, field="Amount", minimum=Decimal("0.01")):
    text = (text or "").strip().replace(",", "")
    try:
        value = Decimal(text)
    except InvalidOperation:
        raise ValidationError(f"{field} must be a valid number.")
    if not value.is_finite():
        raise ValidationError(f"{field} must be a valid number.")
    if value <= 0:
        raise ValidationError(f"{field} must be greater than zero.")
    if value.as_tuple().exponent < -2:
        raise ValidationError(f"{field} can have at most 2 decimal places.")
    if value < minimum:
        raise ValidationError(f"{field} must be at least {inr(minimum)}.")
    if value > MAX_TXN_AMOUNT:
        raise ValidationError(f"{field} cannot exceed {inr(MAX_TXN_AMOUNT)} per transaction.")
    return value.quantize(Decimal("0.01"))


def validate_pin(pin, field="PIN"):
    if not re.fullmatch(r"\d{4,6}", pin or ""):
        raise ValidationError(f"{field} must be 4 to 6 digits.")
    return pin


def validate_registration(raw):
    """Validate the registration form; returns a cleaned dict or raises ValidationError."""
    c = {k: (v or "").strip() for k, v in raw.items()}
    required = {
        "full_name": "Full name", "dob": "Date of birth", "gender": "Gender",
        "mobile": "Mobile number", "email": "Email", "address": "Address",
        "id_number": "Aadhaar/ID number", "account_type": "Account type",
        "deposit": "Initial deposit", "pin": "PIN", "pin2": "Confirm PIN",
    }
    for key, label in required.items():
        if not c.get(key):
            raise ValidationError(f"{label} is required.")
    if not re.fullmatch(r"[A-Za-z][A-Za-z .'-]{1,59}", c["full_name"]):
        raise ValidationError("Full name may contain only letters, spaces, . ' - (2-60 chars).")
    try:
        dob = datetime.strptime(c["dob"], "%d-%m-%Y")
    except ValueError:
        raise ValidationError("Date of birth must be in DD-MM-YYYY format.")
    today = datetime.now()
    age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
    if dob > today or age > 120:
        raise ValidationError("Please enter a valid date of birth.")
    if age < 18:
        raise ValidationError("Customer must be at least 18 years old.")
    if c["gender"] not in ("Male", "Female", "Other"):
        raise ValidationError("Please select a gender.")
    if not re.fullmatch(r"[6-9]\d{9}", c["mobile"]):
        raise ValidationError("Mobile number must be 10 digits starting with 6-9.")
    if not re.fullmatch(r"[\w.+-]+@[\w-]+(\.[\w-]+)+", c["email"]):
        raise ValidationError("Please enter a valid email address.")
    if len(c["address"]) < 5:
        raise ValidationError("Address is too short.")
    id_clean = re.sub(r"[\s-]", "", c["id_number"])
    if not re.fullmatch(r"[A-Za-z0-9]{6,20}", id_clean):
        raise ValidationError("Aadhaar/ID number must be 6-20 letters or digits.")
    if c["account_type"] not in ACCOUNT_TYPES:
        raise ValidationError("Please select an account type.")
    deposit = parse_amount(c["deposit"], "Initial deposit", MIN_INITIAL_DEPOSIT)
    validate_pin(c["pin"])
    if c["pin"] != c["pin2"]:
        raise ValidationError("PIN and Confirm PIN do not match.")
    return {
        "full_name": c["full_name"], "dob": dob.strftime("%Y-%m-%d"), "gender": c["gender"],
        "mobile": c["mobile"], "email": c["email"].lower(), "address": c["address"],
        "id_number": id_clean, "account_type": c["account_type"], "deposit": deposit,
        "pin": c["pin"],
    }


def validate_contact(name, mobile, email, address):
    name, mobile, email, address = (x.strip() for x in (name, mobile, email, address))
    if not re.fullmatch(r"[A-Za-z][A-Za-z .'-]{1,59}", name):
        raise ValidationError("Full name may contain only letters, spaces, . ' - (2-60 chars).")
    if not re.fullmatch(r"[6-9]\d{9}", mobile):
        raise ValidationError("Mobile number must be 10 digits starting with 6-9.")
    if not re.fullmatch(r"[\w.+-]+@[\w-]+(\.[\w-]+)+", email):
        raise ValidationError("Please enter a valid email address.")
    if len(address) < 5:
        raise ValidationError("Address is too short.")
    return name, mobile, email.lower(), address


def mask_name(name):
    return " ".join(w[0] + "*" * (len(w) - 1) if len(w) > 1 else w for w in name.split())


# --------------------------------------------------------------------------
# Database layer
# --------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS customers (
    customer_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name     TEXT NOT NULL,
    date_of_birth TEXT NOT NULL,
    gender        TEXT NOT NULL,
    mobile        TEXT NOT NULL,
    email         TEXT NOT NULL,
    address       TEXT NOT NULL,
    id_number     TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS accounts (
    account_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id    INTEGER NOT NULL REFERENCES customers(customer_id) ON DELETE CASCADE,
    account_number TEXT NOT NULL UNIQUE,
    account_type   TEXT NOT NULL CHECK (account_type IN ('Savings','Current')),
    balance        REAL NOT NULL DEFAULT 0 CHECK (balance >= 0),
    pin_hash       TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','INACTIVE')),
    created_at     TEXT NOT NULL
);
-- No foreign key on transactions.account_number on purpose: the audit trail must
-- survive even if an (empty) account is later deleted by an administrator.
CREATE TABLE IF NOT EXISTS transactions (
    transaction_id   TEXT PRIMARY KEY,
    account_number   TEXT NOT NULL,
    transaction_type TEXT NOT NULL
        CHECK (transaction_type IN ('DEPOSIT','WITHDRAWAL','TRANSFER_OUT','TRANSFER_IN')),
    amount           REAL NOT NULL CHECK (amount > 0),
    description      TEXT,
    related_account  TEXT,
    balance_after    REAL,
    transaction_date TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_txn_account ON transactions(account_number);
CREATE TABLE IF NOT EXISTS admin_users (
    admin_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL
);
"""

ACCOUNT_SELECT = """
SELECT a.account_id, a.account_number, a.account_type, a.balance, a.status,
       a.created_at AS opened, c.customer_id, c.full_name, c.date_of_birth, c.gender,
       c.mobile, c.email, c.address, c.id_number
FROM accounts a JOIN customers c ON c.customer_id = a.customer_id
"""


def D(value):
    return Decimal(str(round(value, 2)))


class BankDB:
    def __init__(self, path=DB_FILE, log_path=LOG_FILE):
        self.log_path, self._pending = log_path, []
        # isolation_level=None -> we control BEGIN/COMMIT/ROLLBACK explicitly
        self.conn = sqlite3.connect(path, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)
        if self.conn.execute("SELECT COUNT(*) FROM admin_users").fetchone()[0] == 0:
            self.conn.execute(
                "INSERT INTO admin_users (username, password_hash) VALUES (?, ?)",
                ("admin", hash_secret("admin@123")),
            )

    def close(self):
        self.conn.close()

    @contextmanager
    def tx(self):
        """All-or-nothing database transaction."""
        cur = self.conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        self._pending = []
        try:
            yield cur
            cur.execute("COMMIT")
        except sqlite3.Error as ex:      # exception handling: turn DB failures into friendly errors
            cur.execute("ROLLBACK")
            raise BankError(f"Database error: {ex}") from ex
        except BaseException:
            cur.execute("ROLLBACK")
            raise
        self._flush_log()                # only committed transactions reach the log file

    # ---- internal helpers ------------------------------------------------
    @staticmethod
    def _new_txn_id():
        return "TXN" + datetime.now().strftime("%y%m%d%H%M%S") + secrets.token_hex(3).upper()

    def _insert_txn(self, cur, acc, ttype, amount, desc, related, balance_after, when, tid=None):
        tid = tid or BankDB._new_txn_id()
        self._pending.append([tid, when, acc, ttype, f"{amount:.2f}", desc, related or "", f"{balance_after:.2f}"])
        cur.execute(
            "INSERT INTO transactions (transaction_id, account_number, transaction_type, amount, "
            "description, related_account, balance_after, transaction_date) VALUES (?,?,?,?,?,?,?,?)",
            (tid, acc, ttype, float(amount), desc, related, float(balance_after), when),
        )
        return tid

    @staticmethod
    def _active_account(cur, acc_no, role="Account"):
        row = cur.execute(
            "SELECT a.account_number, a.balance, a.status, c.full_name FROM accounts a "
            "JOIN customers c ON c.customer_id = a.customer_id WHERE a.account_number = ?",
            (acc_no,),
        ).fetchone()
        if row is None:
            raise BankError(f"{role} not found.")
        if row["status"] != "ACTIVE":
            raise BankError(f"{role} is inactive. Please contact the bank.")
        return row

    # ---- customer operations ---------------------------------------------
    def _flush_log(self):
        # Append committed transactions to a CSV log file; a file problem never breaks banking.
        try:
            is_new = not os.path.exists(self.log_path)
            with open(self.log_path, "a", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                if is_new:
                    w.writerow(CSV_HEADER)
                w.writerows(self._pending)
        except OSError:
            pass
        self._pending = []

    @staticmethod
    def _check_limits(cur, acc_no, balance, amount):
        if balance - amount < MIN_BALANCE:
            raise BankError(f"A minimum balance of {inr(MIN_BALANCE)} must be maintained.")
        used = cur.execute(
            "SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE account_number = ? "
            "AND transaction_type IN ('WITHDRAWAL','TRANSFER_OUT') AND transaction_date LIKE ?",
            (acc_no, datetime.now().strftime("%Y-%m-%d") + "%")).fetchone()[0]
        if D(used) + amount > DAILY_LIMIT:
            raise BankError(f"Daily limit of {inr(DAILY_LIMIT)} exceeded. "
                            f"Remaining today: {inr(max(DAILY_LIMIT - D(used), 0))}")

    def update_customer(self, acc_no, name, mobile, email, address):
        vals = validate_contact(name, mobile, email, address)
        with self.tx() as cur:
            cur.execute("UPDATE customers SET full_name = ?, mobile = ?, email = ?, address = ? WHERE customer_id = "
                        "(SELECT customer_id FROM accounts WHERE account_number = ?)", (*vals, acc_no))

    @staticmethod
    def export_csv(path, rows):
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(CSV_HEADER)
            for r in rows:
                w.writerow([r["transaction_id"], r["transaction_date"], r["account_number"], r["transaction_type"],
                            f"{r['amount']:.2f}", r["description"] or "", r["related_account"] or "",
                            "" if r["balance_after"] is None else f"{r['balance_after']:.2f}"])

    def register_customer(self, d):
        now = now_str()
        with self.tx() as cur:
            cur.execute(
                "INSERT INTO customers (full_name, date_of_birth, gender, mobile, email, address, "
                "id_number, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (d["full_name"], d["dob"], d["gender"], d["mobile"], d["email"], d["address"],
                 d["id_number"], now),
            )
            cust_id = cur.lastrowid
            for _ in range(25):
                acc_no = "1000" + "".join(str(secrets.randbelow(10)) for _ in range(8))
                if not cur.execute("SELECT 1 FROM accounts WHERE account_number = ?", (acc_no,)).fetchone():
                    break
            else:
                raise BankError("Could not generate a unique account number. Please retry.")
            cur.execute(
                "INSERT INTO accounts (customer_id, account_number, account_type, balance, pin_hash, "
                "status, created_at) VALUES (?,?,?,?,?,'ACTIVE',?)",
                (cust_id, acc_no, d["account_type"], float(d["deposit"]), hash_secret(d["pin"]), now),
            )
            tid = self._insert_txn(cur, acc_no, "DEPOSIT", d["deposit"], "Initial deposit", None,
                                   d["deposit"], now)
        return acc_no, tid

    def authenticate(self, acc_no, pin):
        row = self.conn.execute(
            "SELECT account_number, pin_hash, status FROM accounts WHERE account_number = ?",
            (acc_no,),
        ).fetchone()
        if row is None or not verify_secret(pin, row["pin_hash"]):
            raise BankError("Invalid account number or PIN.")
        if row["status"] != "ACTIVE":
            raise BankError("Your account has been deactivated. Please contact the bank.")
        return row["account_number"]

    def get_account(self, acc_no):
        return self.conn.execute(ACCOUNT_SELECT + " WHERE a.account_number = ?", (acc_no,)).fetchone()

    def holder_name(self, acc_no):
        row = self.conn.execute(
            "SELECT c.full_name FROM accounts a JOIN customers c ON c.customer_id = a.customer_id "
            "WHERE a.account_number = ?", (acc_no,)).fetchone()
        return row["full_name"] if row else None

    def deposit(self, acc_no, amount):
        now = now_str()
        with self.tx() as cur:
            acc = self._active_account(cur, acc_no)
            new_bal = D(acc["balance"]) + amount
            cur.execute("UPDATE accounts SET balance = ? WHERE account_number = ?", (float(new_bal), acc_no))
            tid = self._insert_txn(cur, acc_no, "DEPOSIT", amount, "Cash deposit", None, new_bal, now)
        return {"transaction_id": tid, "date": now, "amount": amount, "balance": new_bal}

    def withdraw(self, acc_no, amount):
        now = now_str()
        with self.tx() as cur:
            acc = self._active_account(cur, acc_no)
            if D(acc["balance"]) < amount:
                raise BankError(f"Insufficient balance. Available: {inr(acc['balance'])}")
            self._check_limits(cur, acc_no, D(acc["balance"]), amount)
            new_bal = D(acc["balance"]) - amount
            cur.execute("UPDATE accounts SET balance = ? WHERE account_number = ?", (float(new_bal), acc_no))
            tid = self._insert_txn(cur, acc_no, "WITHDRAWAL", amount, "Cash withdrawal", None, new_bal, now)
        return {"transaction_id": tid, "date": now, "amount": amount, "balance": new_bal}

    def transfer(self, from_acc, to_acc, amount):
        """Atomic transfer: either both balances + both ledger rows change, or nothing does."""
        if from_acc == to_acc:
            raise BankError("You cannot transfer money to the same account.")
        now = now_str()
        base = self._new_txn_id()
        with self.tx() as cur:
            src = self._active_account(cur, from_acc, "Your account")
            dst = self._active_account(cur, to_acc, "Receiver account")
            if D(src["balance"]) < amount:
                raise BankError(f"Insufficient balance. Available: {inr(src['balance'])}")
            self._check_limits(cur, from_acc, D(src["balance"]), amount)
            src_bal = D(src["balance"]) - amount
            dst_bal = D(dst["balance"]) + amount
            cur.execute("UPDATE accounts SET balance = ? WHERE account_number = ?", (float(src_bal), from_acc))
            cur.execute("UPDATE accounts SET balance = ? WHERE account_number = ?", (float(dst_bal), to_acc))
            out_id = self._insert_txn(cur, from_acc, "TRANSFER_OUT", amount,
                                      f"Transfer to {dst['full_name']} ({to_acc})", to_acc, src_bal, now,
                                      base + "-DR")
            self._insert_txn(cur, to_acc, "TRANSFER_IN", amount,
                             f"Transfer from {src['full_name']} ({from_acc})", from_acc, dst_bal, now,
                             base + "-CR")
        return {"transaction_id": out_id, "date": now, "amount": amount, "balance": src_bal,
                "receiver": dst["full_name"]}

    def history(self, acc_no, limit=None):
        sql = ("SELECT * FROM transactions WHERE account_number = ? "
               "ORDER BY transaction_date DESC, rowid DESC")
        params = [acc_no]
        if limit:
            sql += " LIMIT ?"
            params.append(int(limit))
        return self.conn.execute(sql, params).fetchall()

    def change_pin(self, acc_no, current, new):
        row = self.conn.execute("SELECT pin_hash FROM accounts WHERE account_number = ?", (acc_no,)).fetchone()
        if row is None or not verify_secret(current, row["pin_hash"]):
            raise BankError("Current PIN is incorrect.")
        if current == new:
            raise BankError("New PIN must be different from the current PIN.")
        with self.tx() as cur:
            cur.execute("UPDATE accounts SET pin_hash = ? WHERE account_number = ?",
                        (hash_secret(new), acc_no))

    # ---- admin operations -------------------------------------------------
    def authenticate_admin(self, username, password):
        row = self.conn.execute(
            "SELECT username, password_hash FROM admin_users WHERE username = ?", (username,)).fetchone()
        if row is None or not verify_secret(password, row["password_hash"]):
            raise BankError("Invalid admin username or password.")
        return row["username"]

    def stats(self):
        q = self.conn.execute
        return {
            "customers": q("SELECT COUNT(*) FROM customers").fetchone()[0],
            "accounts": q("SELECT COUNT(*) FROM accounts").fetchone()[0],
            "active": q("SELECT COUNT(*) FROM accounts WHERE status = 'ACTIVE'").fetchone()[0],
            "deposits": q("SELECT COALESCE(SUM(amount),0) FROM transactions WHERE transaction_type = 'DEPOSIT'").fetchone()[0],
            "withdrawals": q("SELECT COALESCE(SUM(amount),0) FROM transactions WHERE transaction_type = 'WITHDRAWAL'").fetchone()[0],
            "transactions": q("SELECT COUNT(*) FROM transactions").fetchone()[0],
            "holdings": q("SELECT COALESCE(SUM(balance),0) FROM accounts").fetchone()[0],
        }

    def list_accounts(self, search="", order=""):
        like = f"%{search}%"
        return self.conn.execute(
            ACCOUNT_SELECT + " WHERE (? = '' OR c.full_name LIKE ? OR c.mobile LIKE ? OR c.email LIKE ? "
            "OR a.account_number LIKE ? OR CAST(c.customer_id AS TEXT) = ?) ORDER BY " + ORDERS.get(order, "a.account_id"),
            (search, like, like, like, like, search),
        ).fetchall()

    def list_transactions(self, acc_search="", ttype="", date_from="", date_to="", min_amt=0, max_amt=1e12, txn_id=""):
        return self.conn.execute(
            "SELECT * FROM transactions WHERE (? = '' OR account_number LIKE ?) "
            "AND (? = '' OR transaction_type = ?) AND (? = '' OR transaction_id LIKE ?) "
            "AND (? = '' OR date(transaction_date) >= ?) AND (? = '' OR date(transaction_date) <= ?) "
            "AND amount >= ? AND amount <= ? ORDER BY transaction_date DESC, rowid DESC",
            (acc_search, f"%{acc_search}%", ttype, ttype, txn_id, f"%{txn_id}%",
             date_from, date_from, date_to, date_to, min_amt, max_amt),
        ).fetchall()

    def set_status(self, acc_no, status):
        if status not in ("ACTIVE", "INACTIVE"):
            raise BankError("Invalid status.")
        with self.tx() as cur:
            cur.execute("UPDATE accounts SET status = ? WHERE account_number = ?", (status, acc_no))

    def delete_account(self, acc_no):
        with self.tx() as cur:
            row = cur.execute("SELECT customer_id, balance FROM accounts WHERE account_number = ?",
                              (acc_no,)).fetchone()
            if row is None:
                raise BankError("Account not found.")
            if D(row["balance"]) > 0:
                raise BankError("Account still holds funds. Settle the balance (withdraw) before deleting, "
                                "or deactivate the account instead.")
            cur.execute("DELETE FROM accounts WHERE account_number = ?", (acc_no,))
            if cur.execute("SELECT 1 FROM accounts WHERE customer_id = ?", (row["customer_id"],)).fetchone() is None:
                cur.execute("DELETE FROM customers WHERE customer_id = ?", (row["customer_id"],))


# --------------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------------
PRIMARY, PRIMARY_DARK = "#0b3d91", "#082c6a"
BG, CARD, BORDER = "#f2f5fa", "#ffffff", "#d5dbe7"
GREEN, RED, MUTED = "#1b7f3b", "#b3261e", "#5b6575"
INK = "#1F2937"
AMBER, DARK_BLUE = "#F4A300", "#071F4D"
FONT, FONT_B = ("Segoe UI", 10), ("Segoe UI", 10, "bold")
TXN_COLUMNS = [
    ("id", "Transaction ID", 170, "w"), ("date", "Date / Time", 135, "w"), ("type", "Type", 105, "w"),
    ("drcr", "Cr/Dr", 60, "center"), ("amount", "Amount", 110, "e"), ("bal", "Balance After", 115, "e"),
    ("rel", "Related Acct", 105, "w"), ("desc", "Description", 280, "w"),
]


class App(tk.Tk):
    def __init__(self, db):
        super().__init__()
        self.db = db
        self.account_no = None
        self.title("PyBank - Bank Management System")
        self.geometry("1100x720")
        self.minsize(980, 650)
        self.configure(bg=BG)
        self._setup_style()
        self.container = tk.Frame(self, bg=BG)
        self.container.pack(fill="both", expand=True)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.show_home()

    def _on_close(self):
        self.db.close()
        self.destroy()

    def _setup_style(self):
        s = ttk.Style(self)
        try:
            s.theme_use("clam")
        except tk.TclError:
            pass
        s.configure(".", font=FONT)
        s.configure("TFrame", background=BG)
        s.configure("TLabel", background=BG, font=FONT)
        s.configure("Card.TLabel", background=CARD)
        s.configure("Muted.TLabel", foreground=MUTED)
        s.configure("H1.TLabel", font=("Segoe UI", 18, "bold"), foreground=PRIMARY)
        s.configure("H2.TLabel", font=("Segoe UI", 14, "bold"), foreground=PRIMARY)
        s.configure("TButton", padding=7)
        s.configure("Primary.TButton", background=PRIMARY, foreground="white", font=FONT_B)
        s.map("Primary.TButton", background=[("active", PRIMARY_DARK)])
        s.configure("Side.TButton", anchor="w", padding=(12, 9), background="#e4eaf6")
        s.map("Side.TButton", background=[("active", "#cdd8ef")])
        s.configure("SideActive.TButton", anchor="w", padding=(12, 9), background=PRIMARY, foreground="white", font=FONT_B)
        s.map("SideActive.TButton", background=[("active", PRIMARY_DARK)])
        s.configure("Danger.TButton", foreground=RED, font=FONT_B)
        s.configure("Treeview", rowheight=26, font=FONT)
        s.configure("Treeview.Heading", font=FONT_B, background="#e4eaf6")
        s.configure("TNotebook.Tab", padding=(16, 8), font=FONT_B)

    # ---- small UI helpers -------------------------------------------------
    def clear(self):
        for job in ("_clock_job", "_auto_job", "_bal_job", "_home_job"):      # stop animations/timers of the old screen
            if getattr(self, job, None):
                self.after_cancel(getattr(self, job))
                setattr(self, job, None)
        for w in self.container.winfo_children():
            w.destroy()

    @staticmethod
    def card(parent, **pack):
        f = tk.Frame(parent, bg=CARD, highlightbackground=BORDER, highlightthickness=1, padx=24, pady=20)
        if pack:
            f.pack(**pack)
        return f

    @staticmethod
    def field(parent, label, var=None, show=None, width=32, values=None):
        ttk.Label(parent, text=label, style="Card.TLabel" if parent.cget("bg") == CARD else "TLabel"
                  ).pack(anchor="w", pady=(8, 2))
        if values:
            w = ttk.Combobox(parent, textvariable=var, values=values, state="readonly", width=width - 3)
        else:
            w = ttk.Entry(parent, textvariable=var, show=show, width=width)
        w.pack(anchor="w")
        return w

    @staticmethod
    def make_tree(parent, columns, height=14):
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=[c[0] for c in columns], show="headings", height=height)
        for cid, head, width, anchor in columns:
            tree.heading(cid, text=head)
            tree.column(cid, width=width, anchor=anchor, stretch=True)
        vs = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        hs = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        tree.tag_configure("credit", foreground=GREEN)
        tree.tag_configure("debit", foreground=RED)
        tree.tag_configure("inactive", foreground="#8a8f99")
        return tree

    @staticmethod
    def fill_transactions(tree, rows):
        tree.delete(*tree.get_children())
        for r in rows:
            credit = r["transaction_type"] in CREDIT_TYPES
            tree.insert("", "end", tags=("credit" if credit else "debit",), values=(
                r["transaction_id"], r["transaction_date"], r["transaction_type"].replace("_", " "),
                "Cr" if credit else "Dr", inr(r["amount"]),
                inr(r["balance_after"]) if r["balance_after"] is not None else "",
                r["related_account"] or "-", r["description"] or ""))

    # ---- dynamic UI helpers -------------------------------------------------
    def highlight(self, name):
        for n, b in getattr(self, "side_btns", {}).items():
            try:
                b.configure(style="SideActive.TButton" if n == name else "Side.TButton")
            except tk.TclError:
                pass

    def toast(self, text, color=GREEN):
        """Non-blocking notification that slides down from the top, then slides away."""
        t = tk.Label(self, text=text, bg=color, fg="white", font=FONT_B, padx=18, pady=10)

        def move(y, target, step, done=None):
            try:
                t.place(relx=0.5, y=y, anchor="n")
            except tk.TclError:
                return
            if (step > 0 and y < target) or (step < 0 and y > target):
                self.after(12, lambda: move(y + step, target, step, done))
            elif done:
                done()

        t.lift()
        move(-50, 14, 6, lambda: self.after(2200, lambda: move(14, -60, -6, t.destroy)))

    def shake(self, w, n=0):
        offs = [-10, 10, -8, 8, -5, 5, -2, 2, 0]
        if n < len(offs):
            try:
                w.place_configure(x=offs[n])
            except tk.TclError:
                return
            self.after(30, lambda: self.shake(w, n + 1))

    def _debounce(self, w, fn, ms=250):
        """Run fn shortly after the user stops typing (live search)."""
        if getattr(w, "_deb", None):
            w.after_cancel(w._deb)
        w._deb = w.after(ms, fn)

    def animate_balance(self, target, steps=18):
        target = float(target)
        start = getattr(self, "_shown_bal", None)
        start = target if start is None else start
        if start == target and self.h_bal.get():
            return
        self._shown_bal = target
        if getattr(self, "_bal_job", None):
            self.after_cancel(self._bal_job)

        def frame(i):
            self.h_bal.set(inr(start + (target - start) * (1 - (1 - i / steps) ** 3)))
            if i < steps:
                self._bal_job = self.after(25, lambda: frame(i + 1))
        frame(0)

    def _tick_clock(self):
        self.h_clock.set(datetime.now().strftime("%a, %d %b %Y   %I:%M:%S %p"))
        self._clock_job = self.after(1000, self._tick_clock)

    def draw_activity_chart(self, parent):
        rows = list(reversed(self.db.history(self.account_no, 7)))
        ttk.Label(parent, text="Recent Activity (last 7 transactions)", style="H2.TLabel").pack(anchor="w", pady=(18, 4))
        W, H = 620, 210
        cv = tk.Canvas(parent, width=W, height=H, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        cv.pack(anchor="w")
        if not rows:
            cv.create_text(W // 2, H // 2, text="No transactions yet", fill=MUTED)
            return
        top = max(r["amount"] for r in rows)
        slot = (W - 40) / len(rows)

        def frame(i):
            try:
                cv.delete("all")
            except tk.TclError:
                return
            k = 1 - (1 - i / 20) ** 3
            for n, r in enumerate(rows):
                credit = r["transaction_type"] in CREDIT_TYPES
                h = (r["amount"] / top) * (H - 80) * k
                x = 25 + n * slot + slot * 0.2
                cv.create_rectangle(x, H - 30 - h, x + slot * 0.6, H - 30, fill=GREEN if credit else RED, outline="")
                cv.create_text(x + slot * 0.3, H - 38 - h, text=inr(r["amount"]), font=("Segoe UI", 8), fill=INK)
                cv.create_text(x + slot * 0.3, H - 16, text=r["transaction_type"].replace("_", " ").title(),
                               font=("Segoe UI", 8), fill=MUTED)
            if i < 20:
                cv.after(18, lambda: frame(i + 1))
        frame(1)

    def count_text(self, label, text):
        """Count a number up from 0 (works for plain numbers and rupee amounts)."""
        m = re.fullmatch(r"(\u20b9)?([\d,]+(?:\.\d+)?)", text)
        if not m:
            label.config(text=text)
            return
        target, money = float(m.group(2).replace(",", "")), bool(m.group(1))

        def frame(i):
            v = target * (1 - (1 - i / 20) ** 3)
            try:
                label.config(text=inr(v) if money else str(int(round(v))))
            except tk.TclError:
                return
            if i < 20:
                label.after(20, lambda: frame(i + 1))
        frame(0)

    def animate_bars(self, cv, data, steps=24):
        if getattr(cv, "_job", None):
            cv.after_cancel(cv._job)
        top = max([v for _, v, _ in data] + [1])

        def frame(i):
            try:
                cv.delete("all")
            except tk.TclError:
                return
            k = 1 - (1 - i / steps) ** 3
            for n, (name, val, col) in enumerate(data):
                y, w = 18 + n * 42, (val / top) * 560 * k
                cv.create_text(10, y + 12, text=name, anchor="w", font=FONT_B, fill=INK)
                cv.create_rectangle(120, y, 120 + max(w, 2), y + 24, fill=col, outline="")
                cv.create_text(130 + w, y + 12, text=inr(val * k), anchor="w", font=FONT, fill=INK)
            if i < steps:
                cv._job = cv.after(20, lambda: frame(i + 1))
        frame(0)

    def report_callback_exception(self, exc, val, tb):
        # Last line of defence: any error inside a button/key handler becomes a pop-up, not a crash.
        if isinstance(val, BankError):
            messagebox.showerror("Error", str(val))
        else:
            messagebox.showerror("Unexpected error", f"Something went wrong:\n{val}\n\nPlease try again or restart the application.")

    def logout(self):
        self.account_no = None
        self.show_home()

    # ---- home / login / register ------------------------------------------
    def show_home(self):
        self.clear()
        self.unbind("<Return>")          # a stale Enter binding from the login screen must not survive
        c = self.container
        c.columnconfigure(0, weight=5, uniform="home")
        c.columnconfigure(1, weight=4, uniform="home")
        c.rowconfigure(0, weight=1)
        tips = ["Every transfer is all-or-nothing: no half-finished payments.",
                "PINs are stored as salted hashes, never as plain text.",
                "Every transaction gets its own unique transaction ID.",
                "Admins see live totals that refresh every 8 seconds."]
        feats = ["Salted-hash PIN security", "Instant, safe fund transfers",
                 "Live balance, charts and analytics", "Works fully offline"]
        state = {"i": 0}

        # ---- left: branded panel (gradient, soft circles, rotating tips) ----
        cv = tk.Canvas(c, bg=PRIMARY, highlightthickness=0)
        cv.grid(row=0, column=0, sticky="nsew")
        top, bottom = (0x0B, 0x3D, 0x91), (0x07, 0x1F, 0x4D)

        def paint(_e=None):
            w, h = cv.winfo_width(), cv.winfo_height()
            if w < 50 or h < 50:
                return
            cv.delete("all")
            for y in range(0, h, 4):
                t = y / h
                col = "#%02x%02x%02x" % tuple(int(top[k] + (bottom[k] - top[k]) * t) for k in range(3))
                cv.create_rectangle(0, y, w, y + 4, fill=col, outline="")
            cv.create_oval(w * 0.45, -h * 0.25, w * 1.25, h * 0.45, fill="#ffffff", stipple="gray12", outline="")
            cv.create_oval(-w * 0.2, h * 0.72, w * 0.5, h * 1.3, fill=AMBER, stipple="gray12", outline="")
            y0 = max(h * 0.2, 70)
            cv.create_text(60, y0, text="\U0001F3E6", font=("Segoe UI Emoji", 38), fill="white", anchor="w")
            cv.create_text(135, y0, text="PyBank", font=("Segoe UI", 38, "bold"), fill="white", anchor="w")
            cv.create_text(62, y0 + 58, text="Bank Management System", font=("Segoe UI", 15), fill="#C9D6F2", anchor="w")
            cv.create_rectangle(62, y0 + 90, 132, y0 + 94, fill=AMBER, outline="")
            cv.create_text(62, y0 + 128, text="Secure. Simple. Smart.", font=("Segoe UI", 22, "bold"), fill="white", anchor="w")
            for n, line in enumerate(feats):
                cv.create_text(64, y0 + 180 + n * 30, text="\u2714  " + line, font=("Segoe UI", 12), fill="#E5ECFA", anchor="w")
            cv.create_text(62, h - 125, text="DID YOU KNOW?", font=("Segoe UI", 9, "bold"), fill=AMBER, anchor="w")
            cv.create_text(62, h - 98, text=tips[state["i"]], tags="tip", font=("Segoe UI", 12, "italic"),
                           fill="white", anchor="nw", width=max(w - 124, 200))
            cv.create_text(62, h - 28, text="Team Technical Govindans", font=("Segoe UI", 10), fill="#9FB4E0", anchor="w")

        def rotate():
            state["i"] = (state["i"] + 1) % len(tips)
            try:
                cv.itemconfigure("tip", text=tips[state["i"]])
            except tk.TclError:
                return
            self._home_job = self.after(3500, rotate)

        cv.bind("<Configure>", paint)
        self._home_job = self.after(3500, rotate)

        # ---- right: welcome + action tiles ----
        right = tk.Frame(c, bg=BG)
        right.grid(row=0, column=1, sticky="nsew")
        inner = tk.Frame(right, bg=BG)
        inner.place(relx=0.5, rely=0.46, anchor="center")
        tk.Label(inner, text="Welcome", font=("Segoe UI", 28, "bold"), fg=PRIMARY, bg=BG).pack(anchor="w")
        tk.Label(inner, text="Choose how you would like to continue", font=("Segoe UI", 11), fg=MUTED,
                 bg=BG).pack(anchor="w", pady=(0, 18))
        tk.Label(right, text="Python  \u2022  Tkinter  \u2022  SQLite   |   Works fully offline",
                 font=("Segoe UI", 9), fg=MUTED, bg=BG).pack(side="bottom", pady=14)

        def tile(icon, title, sub, cmd, primary=False):
            bg = PRIMARY if primary else CARD
            hover = PRIMARY_DARK if primary else "#E8EEF9"
            fg_t, fg_s = ("white", "#C9D6F2") if primary else (INK, MUTED)
            f = tk.Frame(inner, bg=bg, width=400, height=80, cursor="hand2",
                         highlightbackground=PRIMARY if primary else BORDER, highlightthickness=1)
            f.grid_propagate(False)
            f.columnconfigure(1, weight=1)
            f.rowconfigure(0, weight=1)
            f.rowconfigure(1, weight=1)
            ic = tk.Label(f, text=icon, font=("Segoe UI Emoji", 20), bg=bg, fg=fg_t)
            ic.grid(row=0, column=0, rowspan=2, padx=(18, 12))
            tt = tk.Label(f, text=title, font=("Segoe UI", 13, "bold"), bg=bg, fg=fg_t, anchor="w")
            tt.grid(row=0, column=1, sticky="sw")
            sb = tk.Label(f, text=sub, font=("Segoe UI", 9), bg=bg, fg=fg_s, anchor="w")
            sb.grid(row=1, column=1, sticky="nw")
            ar = tk.Label(f, text="\u203A", font=("Segoe UI", 24, "bold"), bg=bg, fg=AMBER if primary else PRIMARY)
            ar.grid(row=0, column=2, rowspan=2, padx=18)
            parts = (f, ic, tt, sb, ar)

            def paint_tile(col):
                for w in parts:
                    w.configure(bg=col)

            def leave(e):
                w = f.winfo_containing(e.x_root, e.y_root)
                if w is not None and str(w).startswith(str(f)):
                    return                      # still inside the tile (moved onto a child label)
                paint_tile(bg)

            for w in parts:
                w.bind("<Enter>", lambda _e: paint_tile(hover))
                w.bind("<Leave>", leave)
                w.bind("<Button-1>", lambda _e: cmd())
            return f

        tiles = [tile("\U0001F464", "Customer Login", "Access your account securely", self.show_login, True),
                 tile("\U0001F4DD", "Open a New Account", "Register in under a minute", self.show_register),
                 tile("\U0001F6E1", "Administrator Login", "Manage customers and transactions", self.show_admin_login)]

        def reveal(f):
            try:
                f.pack(fill="x", pady=7)
            except tk.TclError:
                pass

        for n, f in enumerate(tiles):            # tiles appear one after another
            self.after(150 + n * 160, lambda f=f: reveal(f))

    def show_login(self, prefill=""):
        self.clear()
        box = self.card(self.container)
        box.place(relx=0.5, rely=0.5, anchor="center")
        ttk.Label(box, text="Customer Login", style="H2.TLabel", background=CARD).pack()
        acc, pin = tk.StringVar(value=prefill), tk.StringVar()
        e1 = self.field(box, "Account Number", acc)
        e2 = self.field(box, "PIN", pin, show="\u2022")
        (e2 if prefill else e1).focus_set()

        def do_login(_=None):
            try:
                self.account_no = self.db.authenticate(acc.get().strip(), pin.get())
            except BankError as ex:
                messagebox.showerror("Login failed", str(ex))
                self.shake(box)
                pin.set("")
                return
            self.show_dashboard()

        ttk.Button(box, text="Login", style="Primary.TButton", command=do_login, width=30).pack(pady=(16, 4))
        ttk.Button(box, text="Back", command=self.show_home, width=30).pack()
        self.bind("<Return>", do_login)

    def show_register(self, admin=None):
        self.clear()
        self.unbind("<Return>")
        outer = ttk.Frame(self.container)
        outer.pack(expand=True)
        box = self.card(outer)
        box.pack()
        ttk.Label(box, text="Open a New Account", style="H2.TLabel", background=CARD
                  ).grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 8))
        v = {k: tk.StringVar() for k in ("full_name", "dob", "gender", "mobile", "email", "account_type",
                                         "id_number", "deposit", "address", "pin", "pin2")}
        v["account_type"].set("Savings")
        layout = [
            [("Full Name", "full_name", {}), ("Date of Birth (DD-MM-YYYY)", "dob", {})],
            [("Gender", "gender", {"values": ["Male", "Female", "Other"]}), ("Mobile Number", "mobile", {})],
            [("Email", "email", {}), ("Account Type", "account_type", {"values": list(ACCOUNT_TYPES)})],
            [("Aadhaar / ID Number", "id_number", {}), (f"Initial Deposit (min {inr(MIN_INITIAL_DEPOSIT)})", "deposit", {})],
            [("Address", "address", {"span": True})],
            [("PIN (4-6 digits)", "pin", {"show": "\u2022"}), ("Confirm PIN", "pin2", {"show": "\u2022"})],
        ]
        r = 1
        for row in layout:
            for ci, (label, key, opts) in enumerate(row):
                col = ci * 2
                ttk.Label(box, text=label, style="Card.TLabel").grid(
                    row=r, column=col, columnspan=4 if opts.get("span") else 2, sticky="w", padx=8, pady=(8, 0))
                if "values" in opts:
                    w = ttk.Combobox(box, textvariable=v[key], values=opts["values"], state="readonly", width=33)
                else:
                    w = ttk.Entry(box, textvariable=v[key], show=opts.get("show"),
                                  width=82 if opts.get("span") else 36)
                w.grid(row=r + 1, column=col, columnspan=4 if opts.get("span") else 2, sticky="w", padx=8)
            r += 2

        def submit():
            try:
                clean = validate_registration({k: x.get() for k, x in v.items()})
                acc_no, tid = self.db.register_customer(clean)
            except BankError as ex:
                messagebox.showerror("Registration failed", str(ex))
                return
            messagebox.showinfo(
                "Account created successfully",
                f"Welcome, {clean['full_name']}!\n\nYour account number is:\n\n    {acc_no}\n\n"
                f"Account type: {clean['account_type']}\nInitial deposit: {inr(clean['deposit'])}\n"
                f"Transaction ID: {tid}\n\nPlease remember your account number and PIN.")
            self.show_admin_dashboard(admin) if admin else self.show_login(prefill=acc_no)

        btns = ttk.Frame(box, style="TFrame")
        btns.grid(row=r, column=0, columnspan=4, pady=(18, 0))
        ttk.Button(btns, text="Create Account", style="Primary.TButton", command=submit, width=22).pack(side="left", padx=6)
        ttk.Button(btns, text="Back", command=(lambda: self.show_admin_dashboard(admin)) if admin else self.show_home, width=14).pack(side="left", padx=6)

    # ---- customer dashboard -----------------------------------------------
    def show_dashboard(self):
        self.clear()
        self.unbind("<Return>")
        hdr = tk.Frame(self.container, bg=PRIMARY, padx=20, pady=14)
        hdr.pack(fill="x")
        left = tk.Frame(hdr, bg=PRIMARY)
        left.pack(side="left")
        self.h_name, self.h_info, self.h_bal = tk.StringVar(), tk.StringVar(), tk.StringVar()
        self.h_clock = tk.StringVar()
        self._shown_bal = 0.0          # balance counts up from 0 on login
        tk.Label(left, textvariable=self.h_name, bg=PRIMARY, fg="white", font=("Segoe UI", 16, "bold")).pack(anchor="w")
        tk.Label(left, textvariable=self.h_info, bg=PRIMARY, fg="#c9d6f2", font=FONT).pack(anchor="w")
        right = tk.Frame(hdr, bg=PRIMARY)
        right.pack(side="right")
        tk.Label(right, text="Available Balance", bg=PRIMARY, fg="#c9d6f2", font=FONT).pack(anchor="e")
        tk.Label(right, textvariable=self.h_bal, bg=PRIMARY, fg="white", font=("Segoe UI", 20, "bold")).pack(anchor="e")
        tk.Label(right, textvariable=self.h_clock, bg=PRIMARY, fg="#c9d6f2", font=("Segoe UI", 9)).pack(anchor="e")

        body = ttk.Frame(self.container)
        body.pack(fill="both", expand=True)
        side = ttk.Frame(body, padding=12)
        side.pack(side="left", fill="y")
        actions = [("Balance Enquiry", self.view_balance), ("Deposit", lambda: self.view_cash("deposit")),
                   ("Withdraw", lambda: self.view_cash("withdraw")), ("Transfer Money", self.view_transfer),
                   ("Transaction History", lambda: self.view_history(None)),
                   ("Mini Statement", lambda: self.view_history(10)), ("Account Details", self.view_details),
                   ("Update Details", lambda: self.edit_dialog(self.account_no, False)),
                   ("Change PIN", self.view_change_pin), ("Logout", self.logout)]
        self.side_btns = {}
        for text, cmd in actions:
            b = ttk.Button(side, text=text, style="Side.TButton", width=22,
                           command=lambda c=cmd, t=text: (self.highlight(t), c()))
            b.pack(fill="x", pady=3)
            self.side_btns[text] = b
        self.content = ttk.Frame(body, padding=(8, 12, 16, 12))
        self.content.pack(side="left", fill="both", expand=True)
        self.refresh_header()
        self.view_balance()
        self.highlight("Balance Enquiry")
        self._tick_clock()

    def refresh_header(self):
        a = self.db.get_account(self.account_no)
        self.h_name.set(f"Welcome, {a['full_name']}")
        self.h_info.set(f"Account No: {a['account_number']}   |   {a['account_type']} Account")
        self.animate_balance(a["balance"])

    def set_view(self, title):
        for w in self.content.winfo_children():
            w.destroy()
        ttk.Label(self.content, text=title, style="H2.TLabel").pack(anchor="w", pady=(0, 12))
        return self.content

    @staticmethod
    def render_receipt(parent, heading, rows):
        for w in parent.winfo_children():
            w.destroy()
        box = tk.Frame(parent, bg=CARD, highlightbackground=BORDER, highlightthickness=1, padx=18, pady=14)
        box.pack(anchor="w", pady=14)
        tk.Label(box, text=heading, bg=CARD, fg=GREEN, font=("Segoe UI", 12, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        for i, (k, val) in enumerate(rows, 1):
            tk.Label(box, text=k, bg=CARD, fg=MUTED, font=FONT).grid(row=i, column=0, sticky="w", padx=(0, 24), pady=2)
            tk.Label(box, text=val, bg=CARD, font=FONT_B).grid(row=i, column=1, sticky="w", pady=2)

    def view_balance(self):
        f = self.set_view("Balance Enquiry")
        a = self.db.get_account(self.account_no)   # always read fresh from SQLite
        box = self.card(f)
        box.pack(anchor="w")
        ttk.Label(box, text="Current Balance", style="Card.TLabel").pack(anchor="w")
        tk.Label(box, text=inr(a["balance"]), bg=CARD, fg=PRIMARY, font=("Segoe UI", 30, "bold")).pack(anchor="w")
        ttk.Label(box, text=f"As of {now_str()}", style="Card.TLabel", foreground=MUTED).pack(anchor="w")
        self.draw_activity_chart(f)
        self.refresh_header()

    def view_cash(self, kind):
        dep = kind == "deposit"
        f = self.set_view("Deposit Money" if dep else "Withdraw Money")
        ttk.Label(f, text="Amount (\u20b9)").pack(anchor="w")
        var = tk.StringVar()
        entry = ttk.Entry(f, textvariable=var, width=28)
        entry.pack(anchor="w", pady=4)
        entry.focus_set()
        out = ttk.Frame(f)

        def submit(_=None):
            try:
                amt = parse_amount(var.get())
                res = (self.db.deposit if dep else self.db.withdraw)(self.account_no, amt)
            except BankError as ex:
                messagebox.showerror("Transaction failed", str(ex))
                return
            self.render_receipt(out, "\u2714 Deposit successful" if dep else "\u2714 Withdrawal successful", [
                ("Transaction ID", res["transaction_id"]), ("Date / Time", res["date"]),
                ("Amount", inr(res["amount"])), ("New Balance", inr(res["balance"]))])
            var.set("")
            self.refresh_header()
            self.toast(f"{'Deposited' if dep else 'Withdrawn'} {inr(res['amount'])} successfully")

        entry.bind("<Return>", submit)
        ttk.Button(f, text="Deposit" if dep else "Withdraw", style="Primary.TButton", command=submit).pack(anchor="w", pady=6)
        out.pack(anchor="w", fill="x")

    def view_transfer(self):
        f = self.set_view("Transfer Money")
        to_var, amt_var = tk.StringVar(), tk.StringVar()
        ttk.Label(f, text="Receiver Account Number").pack(anchor="w")
        ttk.Entry(f, textvariable=to_var, width=28).pack(anchor="w", pady=(2, 8))
        ttk.Label(f, text="Amount (\u20b9)").pack(anchor="w")
        ttk.Entry(f, textvariable=amt_var, width=28).pack(anchor="w", pady=(2, 8))
        out = ttk.Frame(f)

        def submit():
            to_acc = to_var.get().strip()
            try:
                if not to_acc.isdigit():
                    raise ValidationError("Receiver account number must contain digits only.")
                if to_acc == self.account_no:
                    raise BankError("You cannot transfer money to the same account.")
                name = self.db.holder_name(to_acc)
                if name is None:
                    raise BankError("Receiver account not found.")
                amt = parse_amount(amt_var.get())
                if not messagebox.askyesno("Confirm transfer",
                                           f"Transfer {inr(amt)} to {mask_name(name)} ({to_acc})?"):
                    return
                res = self.db.transfer(self.account_no, to_acc, amt)
            except BankError as ex:
                messagebox.showerror("Transfer failed", str(ex))
                return
            self.render_receipt(out, "\u2714 Transfer successful", [
                ("Transaction ID", res["transaction_id"]), ("Date / Time", res["date"]),
                ("To", f"{mask_name(res['receiver'])} ({to_acc})"), ("Amount", inr(res["amount"])),
                ("New Balance", inr(res["balance"]))])
            to_var.set("")
            amt_var.set("")
            self.toast(f"Transferred {inr(res['amount'])} successfully")
            self.refresh_header()

        ttk.Button(f, text="Transfer", style="Primary.TButton", command=submit).pack(anchor="w", pady=6)
        out.pack(anchor="w", fill="x")

    def view_history(self, limit):
        f = self.set_view("Mini Statement (Last 10 Transactions)" if limit else "Transaction History")
        q = tk.StringVar()

        def load():
            kw = q.get().strip().lower()
            rows = [r for r in self.db.history(self.account_no, limit) if not kw or kw in " ".join(
                str(r[k]) for k in ("transaction_id", "transaction_date", "transaction_type", "amount", "description")).lower()]
            self.fill_transactions(tree, rows)

        if not limit:
            bar = ttk.Frame(f)
            bar.pack(fill="x", pady=(0, 8))
            ttk.Label(bar, text="Search (ID / date / type / amount / text):").pack(side="left")
            ttk.Entry(bar, textvariable=q, width=26).pack(side="left", padx=6)
            q.trace_add("write", lambda *_: self._debounce(bar, load))
            ttk.Button(bar, text="Search", style="Primary.TButton", command=load).pack(side="left")
        tree = self.make_tree(f, TXN_COLUMNS)
        load()
        ttk.Button(f, text="Refresh", command=load).pack(anchor="e", pady=(8, 0))

    def view_details(self):
        f = self.set_view("Account Details")
        a = self.db.get_account(self.account_no)
        box = self.card(f)
        box.pack(anchor="w")
        rows = [("Customer Name", a["full_name"]), ("Account Number", a["account_number"]),
                ("Account Type", a["account_type"]), ("Mobile Number", a["mobile"]), ("Email", a["email"]),
                ("Address", a["address"]), ("Account Created", a["opened"]), ("Status", a["status"]),
                ("Current Balance", inr(a["balance"]))]
        for i, (k, val) in enumerate(rows):
            tk.Label(box, text=k, bg=CARD, fg=MUTED, font=FONT).grid(row=i, column=0, sticky="w", padx=(0, 30), pady=4)
            tk.Label(box, text=val, bg=CARD, font=FONT_B, wraplength=420, justify="left").grid(row=i, column=1, sticky="w", pady=4)

    def view_change_pin(self):
        f = self.set_view("Change PIN")
        cur, new, conf = tk.StringVar(), tk.StringVar(), tk.StringVar()
        for label, var in (("Current PIN", cur), ("New PIN (4-6 digits)", new), ("Confirm New PIN", conf)):
            ttk.Label(f, text=label).pack(anchor="w", pady=(6, 2))
            ttk.Entry(f, textvariable=var, show="\u2022", width=28).pack(anchor="w")

        def submit():
            try:
                validate_pin(new.get(), "New PIN")
                if new.get() != conf.get():
                    raise ValidationError("New PIN and confirmation do not match.")
                self.db.change_pin(self.account_no, cur.get(), new.get())
            except BankError as ex:
                messagebox.showerror("Change PIN failed", str(ex))
                return
            for var in (cur, new, conf):
                var.set("")
            self.toast("PIN changed successfully")

        ttk.Button(f, text="Update PIN", style="Primary.TButton", command=submit).pack(anchor="w", pady=14)

    # ---- admin --------------------------------------------------------------
    def edit_dialog(self, acc_no, is_admin, after=None):
        a = self.db.get_account(acc_no)
        win = tk.Toplevel(self)
        win.title("Update Details")
        win.configure(bg=CARD)
        win.resizable(False, False)
        win.grab_set()
        box = tk.Frame(win, bg=CARD, padx=24, pady=18)
        box.pack()
        keys = ("full_name", "mobile", "email", "address")
        vs = {k: tk.StringVar(value=a[k]) for k in keys}
        for label, key in (("Full Name", "full_name"), ("Mobile", "mobile"), ("Email", "email"), ("Address", "address")):
            w = self.field(box, label, vs[key], width=40)
            if key == "full_name" and not is_admin:
                w.state(["disabled"])        # customers cannot change their legal name

        def save():
            try:
                self.db.update_customer(acc_no, *(vs[k].get() for k in keys))
            except BankError as ex:
                messagebox.showerror("Update failed", str(ex), parent=win)
                return
            messagebox.showinfo("Success", "Details updated successfully.", parent=win)
            win.destroy()
            if after:
                after()
            elif not is_admin:
                self.refresh_header()
                self.view_details()

        ttk.Button(box, text="Save Changes", style="Primary.TButton", command=save).pack(pady=(16, 0))

    def show_admin_login(self):
        self.clear()
        box = self.card(self.container)
        box.place(relx=0.5, rely=0.5, anchor="center")
        ttk.Label(box, text="Administrator Login", style="H2.TLabel", background=CARD).pack()
        user, pw = tk.StringVar(), tk.StringVar()
        e1 = self.field(box, "Username", user)
        self.field(box, "Password", pw, show="\u2022")
        e1.focus_set()

        def do_login(_=None):
            try:
                name = self.db.authenticate_admin(user.get().strip(), pw.get())
            except BankError as ex:
                messagebox.showerror("Login failed", str(ex))
                self.shake(box)
                pw.set("")
                return
            self.show_admin_dashboard(name)

        ttk.Button(box, text="Login", style="Primary.TButton", command=do_login, width=30).pack(pady=(16, 4))
        ttk.Button(box, text="Back", command=self.show_home, width=30).pack()
        self.bind("<Return>", do_login)

    def show_admin_dashboard(self, admin_name):
        self.clear()
        self.unbind("<Return>")
        self.admin_name = admin_name
        hdr = tk.Frame(self.container, bg=PRIMARY, padx=20, pady=12)
        hdr.pack(fill="x")
        tk.Label(hdr, text=f"Admin Console  -  {admin_name}", bg=PRIMARY, fg="white",
                 font=("Segoe UI", 15, "bold")).pack(side="left")
        tk.Label(hdr, text="\u25cf LIVE  (overview refreshes every 8 s)", bg=PRIMARY, fg="#7CFC98", font=("Segoe UI", 9, "bold")).pack(side="left", padx=18)
        ttk.Button(hdr, text="Logout", command=self.show_home).pack(side="right")
        nb = ttk.Notebook(self.container)
        nb.pack(fill="both", expand=True, padx=12, pady=12)
        loaders = []

        # Overview
        ov = ttk.Frame(nb, padding=16)
        nb.add(ov, text="Overview")
        cards = ttk.Frame(ov)
        cards.pack(anchor="w")
        chart = tk.Canvas(ov, width=860, height=140, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        chart.pack(anchor="w", padx=8, pady=(4, 0))

        def load_overview():
            for w in cards.winfo_children():
                w.destroy()
            s = self.db.stats()
            items = [("Total Customers", s["customers"]), ("Total Accounts", f"{s['accounts']} ({s['active']} active)"),
                     ("Total Deposits", inr(s["deposits"])), ("Total Withdrawals", inr(s["withdrawals"])),
                     ("Total Transactions", s["transactions"]), ("Funds Held", inr(s["holdings"]))]
            for i, (k, val) in enumerate(items):
                c = self.card(cards)
                c.grid(row=i // 3, column=i % 3, padx=8, pady=8, sticky="nsew")
                tk.Label(c, text=k, bg=CARD, fg=MUTED, font=FONT).pack(anchor="w")
                lbl = tk.Label(c, text="", bg=CARD, fg=PRIMARY, font=("Segoe UI", 18, "bold"))
                lbl.pack(anchor="w")
                self.count_text(lbl, str(val))
            self.animate_bars(chart, [("Deposits", s["deposits"], GREEN), ("Withdrawals", s["withdrawals"], RED),
                                      ("Funds held", s["holdings"], PRIMARY)])

        loaders.append(load_overview)
        ttk.Button(ov, text="Refresh", command=load_overview).pack(anchor="w", padx=8, pady=8)

        # Customers + Accounts tabs
        for kind in ("customers", "accounts"):
            loaders.append(self._admin_account_tab(nb, kind, loaders))
        # Transactions tab
        loaders.append(self._admin_txn_tab(nb))
        loaders.append(self._admin_analysis_tab(nb))

        def reload_all(_=None):
            for fn in loaders:
                fn()

        nb.bind("<<NotebookTabChanged>>", reload_all)

        def auto():
            try:
                if nb.index("current") == 0:      # only the overview auto-refreshes
                    load_overview()
            except tk.TclError:
                return
            self._auto_job = self.after(8000, auto)

        self._auto_job = self.after(8000, auto)
        reload_all()

    def _admin_account_tab(self, nb, kind, loaders):
        tab = ttk.Frame(nb, padding=10)
        nb.add(tab, text="Customer Management" if kind == "customers" else "Account Management")
        bar = ttk.Frame(tab)
        bar.pack(fill="x", pady=(0, 8))
        q = tk.StringVar()
        ttk.Label(bar, text="Search (name / mobile / email / account no / customer ID):").pack(side="left")
        ent = ttk.Entry(bar, textvariable=q, width=28)
        q.trace_add("write", lambda *_: self._debounce(ent, lambda: load()))   # live search as you type
        ent.pack(side="left", padx=6)
        if kind == "customers":
            cols = [("cid", "Cust. ID", 70, "center"), ("name", "Name", 170, "w"), ("mobile", "Mobile", 110, "w"),
                    ("email", "Email", 200, "w"), ("acc", "Account No", 120, "w"), ("type", "Type", 75, "w"),
                    ("bal", "Balance", 120, "e"), ("status", "Status", 80, "center")]
        else:
            cols = [("aid", "Acct ID", 70, "center"), ("acc", "Account No", 120, "w"), ("name", "Holder", 170, "w"),
                    ("type", "Type", 80, "w"), ("bal", "Balance", 120, "e"), ("status", "Status", 80, "center"),
                    ("opened", "Opened On", 150, "w")]
        tree = self.make_tree(tab, cols)

        def load():
            tree.delete(*tree.get_children())
            for r in self.db.list_accounts(q.get().strip()):
                if kind == "customers":
                    vals = (r["customer_id"], r["full_name"], r["mobile"], r["email"], r["account_number"],
                            r["account_type"], inr(r["balance"]), r["status"])
                else:
                    vals = (r["account_id"], r["account_number"], r["full_name"], r["account_type"],
                            inr(r["balance"]), r["status"], r["opened"])
                tree.insert("", "end", iid=r["account_number"], values=vals,
                            tags=("inactive",) if r["status"] != "ACTIVE" else ())

        def selected():
            sel = tree.selection()
            if not sel:
                messagebox.showinfo("Select a row", "Please select a row first.")
                return None
            return sel[0]

        def view():
            acc = selected()
            if acc:
                a = self.db.get_account(acc)
                messagebox.showinfo("Account details", (
                    f"Name: {a['full_name']}\nCustomer ID: {a['customer_id']}\nAccount No: {a['account_number']}\n"
                    f"Type: {a['account_type']}\nStatus: {a['status']}\nBalance: {inr(a['balance'])}\n"
                    f"DOB: {a['date_of_birth']}\nGender: {a['gender']}\nMobile: {a['mobile']}\nEmail: {a['email']}\n"
                    f"Address: {a['address']}\nID number: ****{a['id_number'][-4:]}\nCreated: {a['opened']}"))

        def toggle():
            acc = selected()
            if not acc:
                return
            current = self.db.get_account(acc)["status"]
            new = "INACTIVE" if current == "ACTIVE" else "ACTIVE"
            if messagebox.askyesno("Confirm", f"Set account {acc} to {new}?"):
                self.db.set_status(acc, new)
                for fn in loaders:
                    fn()

        def delete():
            acc = selected()
            if not acc:
                return
            if messagebox.askyesno("Delete account", f"Permanently delete account {acc} and its customer record?\n"
                                                     "(Transaction history is kept for audit.)\nThis cannot be undone.", icon="warning"):
                try:
                    self.db.delete_account(acc)
                except BankError as ex:
                    messagebox.showerror("Cannot delete", str(ex))
                    return
                for fn in loaders:
                    fn()

        ttk.Button(bar, text="Search", style="Primary.TButton", command=load).pack(side="left", padx=2)
        ttk.Button(bar, text="Clear", command=lambda: (q.set(""), load())).pack(side="left", padx=2)
        ent.bind("<Return>", lambda _e: load())
        btns = ttk.Frame(tab)
        btns.pack(fill="x", pady=(8, 0))
        def edit():
            acc = selected()
            if acc:
                self.edit_dialog(acc, True, lambda: [fn() for fn in loaders])

        ttk.Button(btns, text="View Details", command=view).pack(side="left", padx=2)
        if kind == "customers":
            ttk.Button(btns, text="Add Customer", command=lambda: self.show_register(self.admin_name)).pack(side="left", padx=2)
            ttk.Button(btns, text="Edit Details", command=edit).pack(side="left", padx=2)
        ttk.Button(btns, text="Activate / Deactivate", command=toggle).pack(side="left", padx=2)
        if kind == "customers":
            ttk.Button(btns, text="Delete Account", style="Danger.TButton", command=delete).pack(side="left", padx=2)
        return load

    def _admin_analysis_tab(self, nb):
        tab = ttk.Frame(nb, padding=10)
        nb.add(tab, text="Account Analysis")
        summary = ttk.Label(tab, font=FONT_B, wraplength=900, justify="left")
        summary.pack(anchor="w", pady=(0, 8))
        bar = ttk.Frame(tab)
        bar.pack(fill="x", pady=(0, 8))
        thr, order = tk.StringVar(value=str(LOW_BALANCE_DEFAULT)), tk.StringVar(value="Highest first")
        ttk.Label(bar, text="Low-balance threshold (\u20b9):").pack(side="left")
        ttk.Entry(bar, textvariable=thr, width=10).pack(side="left", padx=6)
        ttk.Label(bar, text="Sort customers by balance:").pack(side="left", padx=(16, 0))
        combo = ttk.Combobox(bar, textvariable=order, values=("Highest first", "Lowest first"), state="readonly", width=14)
        combo.pack(side="left", padx=6)
        cols = [("acc", "Account No", 120, "w"), ("name", "Customer", 200, "w"), ("type", "Type", 80, "w"),
                ("bal", "Balance", 130, "e"), ("status", "Status", 80, "center"), ("note", "Note", 150, "w")]
        tree = self.make_tree(tab, cols)

        def load(_e=None):
            try:
                t = parse_amount(thr.get(), "Threshold")
            except BankError as ex:
                messagebox.showerror("Invalid threshold", str(ex))
                return
            rows = self.db.list_accounts("", "low" if order.get() == "Lowest first" else "high")
            top = max(rows, key=lambda r: r["balance"], default=None)
            low_count = sum(1 for r in rows if r["balance"] < float(t))
            st = self.db.stats()
            summary.config(text="No accounts yet." if top is None else
                           f"Highest balance: {inr(top['balance'])} ({top['full_name']}, {top['account_number']})   |   "
                           f"Low-balance accounts (below {inr(t)}): {low_count}   |   "
                           f"Total deposits: {inr(st['deposits'])}   |   Funds held: {inr(st['holdings'])}")
            tree.delete(*tree.get_children())
            for r in rows:
                low = r["balance"] < float(t)
                tree.insert("", "end", tags=("debit",) if low else (), values=(
                    r["account_number"], r["full_name"], r["account_type"], inr(r["balance"]), r["status"],
                    "LOW BALANCE" if low else ""))

        ttk.Button(bar, text="Apply", style="Primary.TButton", command=load).pack(side="left", padx=2)
        combo.bind("<<ComboboxSelected>>", load)
        return load

    def _admin_txn_tab(self, nb):
        tab = ttk.Frame(nb, padding=10)
        nb.add(tab, text="Transaction Management")
        bar = ttk.Frame(tab)
        bar.pack(fill="x", pady=(0, 8))
        acc_var, type_var = tk.StringVar(), tk.StringVar(value="ALL")
        ttk.Label(bar, text="Account No:").pack(side="left")
        ent = ttk.Entry(bar, textvariable=acc_var, width=20)
        ent.pack(side="left", padx=6)
        ttk.Label(bar, text="Type:").pack(side="left")
        ttk.Combobox(bar, textvariable=type_var, values=("ALL",) + TXN_TYPES, state="readonly", width=15
                     ).pack(side="left", padx=6)
        bar2 = ttk.Frame(tab)
        bar2.pack(fill="x", pady=(0, 8))
        df, dt, mn, mx, tid = (tk.StringVar() for _ in range(5))
        for label, var, w in (("Txn ID:", tid, 16), ("From (YYYY-MM-DD):", df, 11), ("To:", dt, 11), ("Min \u20b9:", mn, 9), ("Max \u20b9:", mx, 9)):
            ttk.Label(bar2, text=label).pack(side="left", padx=(8, 0))
            ttk.Entry(bar2, textvariable=var, width=w).pack(side="left", padx=4)

        def fetch():
            try:
                for d in (df.get().strip(), dt.get().strip()):
                    if d:
                        datetime.strptime(d, "%Y-%m-%d")
                lo = parse_amount(mn.get(), "Min amount") if mn.get().strip() else 0
                hi = parse_amount(mx.get(), "Max amount") if mx.get().strip() else 1e12
            except ValueError:
                messagebox.showerror("Invalid filter", "Dates must be in YYYY-MM-DD format.")
                return None
            except BankError as ex:
                messagebox.showerror("Invalid filter", str(ex))
                return None
            ttype = "" if type_var.get() == "ALL" else type_var.get()
            return self.db.list_transactions(acc_var.get().strip(), ttype, df.get().strip(), dt.get().strip(),
                                             float(lo), float(hi), tid.get().strip())

        def export():
            rows = fetch()
            if rows is None:
                return
            path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV file", "*.csv")],
                                                initialfile="transactions_export.csv")
            if path:
                try:
                    self.db.export_csv(path, rows)
                except OSError as ex:
                    messagebox.showerror("Export failed", str(ex))
                    return
                messagebox.showinfo("Exported", f"{len(rows)} transaction(s) saved to:\n{path}")

        ttk.Button(bar2, text="Export CSV", command=export).pack(side="right", padx=2)
        cols = [("acc", "Account No", 115, "w")] + TXN_COLUMNS
        tree = self.make_tree(tab, cols)

        def load():
            tree.delete(*tree.get_children())
            ttype = "" if type_var.get() == "ALL" else type_var.get()
            rows = fetch()
            if rows is None:
                return
            for r in rows:
                credit = r["transaction_type"] in CREDIT_TYPES
                tree.insert("", "end", tags=("credit" if credit else "debit",), values=(
                    r["account_number"], r["transaction_id"], r["transaction_date"],
                    r["transaction_type"].replace("_", " "), "Cr" if credit else "Dr", inr(r["amount"]),
                    inr(r["balance_after"]) if r["balance_after"] is not None else "",
                    r["related_account"] or "-", r["description"] or ""))

        ttk.Button(bar, text="Search", style="Primary.TButton", command=load).pack(side="left", padx=2)
        for v in (acc_var, tid):
            v.trace_add("write", lambda *_: self._debounce(tab, load))   # live filter
        ttk.Button(bar, text="Clear", command=lambda: ([v.set("") for v in (acc_var, df, dt, mn, mx, tid)], type_var.set("ALL"), load())).pack(side="left", padx=2)
        ent.bind("<Return>", lambda _e: load())
        return load


def main():
    try:
        db = BankDB()
    except sqlite3.Error as ex:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Database error", f"Could not open the database:\n{ex}")
        return
    App(db).mainloop()


if __name__ == "__main__":
    main()
