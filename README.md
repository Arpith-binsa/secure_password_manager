# Secure Password Manager

A Flask-based password manager implementing:

- User registration and authentication
- Password hashing with salting
- AES-256-GCM encryption for stored vault entries
- Scrypt-based encryption-key derivation
- Password generation
- SQLite database storage
- CSRF protection
- SQL injection-resistant ORM queries
- XSS protection through Jinja template escaping
- Secure session-cookie settings
- Basic account lockout after repeated failed logins

## 1. Requirements

Python 3.11 or newer is recommended.

## 2. One-command setup

From the project directory:

```bash
python setup.py
```

The script creates `.venv`, installs dependencies and creates the SQLite database.

## 3. Run

Windows:

```powershell
.venv\Scripts\python.exe app.py
```

macOS/Linux:

```bash
.venv/bin/python app.py
```

Open `http://127.0.0.1:5000`.

## 4. Security design

The master password is never stored in the database or browser session. A password hash generated with Werkzeug's scrypt support is stored for authentication.

Each user also receives a random 16-byte encryption salt. After successful login, the master password is used with Scrypt to derive a 256-bit encryption key. For this implementation, the derived key is kept only in the server process memory while the user is signed in; the browser session contains only a random vault token. Vault records are encrypted with AES-256-GCM using a fresh 12-byte nonce for every record. AES-GCM provides confidentiality and integrity.

The database therefore stores encrypted credential data rather than plaintext passwords.

Flask-WTF provides CSRF tokens for state-changing forms. SQLAlchemy uses parameterized database operations. Jinja escapes template output by default, reducing reflected and stored XSS risk. Session cookies are HTTP-only and SameSite=Lax.

Five consecutive failed login attempts temporarily lock the account for five minutes.
