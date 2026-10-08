# Smart Banking

**Bank Management System Using Only Python**

A complete desktop banking simulator built with **pure Python**: a **Tkinter** graphical interface and an **SQLite** database. It runs fully offline and uses **only the Python standard library** (no `pip install` needed).

**Team:** Technical Govindans — Vighnnajit.B, Shri Vasanth.V

## Features

### Customer
- Open an account with a validated registration form (unique 12-digit account number generated)
- Secure login with account number and PIN (PIN masked while typing)
- Dashboard with name, account number, account type and live balance
- Deposit, withdraw, and transfer money to another account
- Transaction history with search, and a mini statement (last 10 transactions)
- Account details, update contact details, change PIN, logout

### Admin
- Separate administrator login
- Overview dashboard: customers, accounts, deposits, withdrawals, transactions, funds held
- Customer management: add, view, search, edit, delete
- Account management: activate / deactivate accounts
- Transaction management: filter by account, type, transaction ID, date range and amount; export to CSV
- Account analysis: highest balance, low-balance accounts, total deposits, customers sorted by balance

### Interface
Animated balance counter, live clock, activity charts, toast notifications, live search, and an auto-refreshing admin overview, all with plain Tkinter.

## Rules and limits
| Rule | Value |
|---|---|
| Maximum per transaction | ₹10,00,000 |
| Daily limit (withdrawals + transfers out) | ₹2,00,000 per account |
| Minimum balance kept | ₹100 |
| Minimum initial deposit | ₹500 |
| PIN | 4 to 6 digits |
| Customer age | 18 or older |

Every committed transaction is also appended to `transactions_log.csv`.

## Security
- PINs and passwords stored as **salted PBKDF2-SHA256** hashes (200,000 rounds), never as plain text
- All SQL is **parameterized** (protects against SQL injection)
- Registration and transfers run in **one database transaction**: all steps succeed or nothing changes
- Money is calculated with `Decimal`, not `float`
- Wrong account number and wrong PIN give the same error message

## How to run
Requirements: Python 3.8+ with Tkinter (included in the standard Windows and macOS installers; on Ubuntu/Debian run `sudo apt install python3-tk`).

```bash
python bank_system.py
```

The database file `bank.db` is created automatically on first run.

**Default admin (prototype only):** username `admin`, password `admin@123`. Change this before any real use.

## Project structure
```
bank_system.py   # the whole application
```
Inside `bank_system.py`: helpers (validation, hashing, formatting) → `BankDB` class (SQL and banking rules) → `App` class (Tkinter screens). The screens never write SQL.

## Database tables
`customers`, `accounts`, `transactions`, `admin_users`

## Known limitations
- Balances are stored as `REAL` (integer paise would be better for production)
- No lockout after repeated wrong PINs
- The admin password cannot be changed inside the app
- Single local user; no real bank integration

## Future scope
Account lockout, PDF statements, interest for savings accounts, admin password change screen, email/SMS alerts, multi-branch support.

## Disclaimer
This is an educational prototype. It simulates banking and must not be used with real money or real customer data.
