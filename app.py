import os
import secrets
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from markupsafe import escape
from sqlalchemy import UniqueConstraint
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import PasswordField, StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo

from crypto_utils import decrypt_json, encrypt_json, derive_encryption_key

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "password_manager.db")

app = Flask(__name__)

app.config.update(
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32),
    SQLALCHEMY_DATABASE_URI=f"sqlite:///{DATABASE_PATH}",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_HTTPS", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    WTF_CSRF_TIME_LIMIT=3600,
)

csrf = CSRFProtect(app)
db = SQLAlchemy(app)


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    encryption_salt = db.Column(db.LargeBinary(16), nullable=False)
    failed_attempts = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class Credential(db.Model):
    __tablename__ = "credentials"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    encrypted_data = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    user = db.relationship(
        "User", backref=db.backref("credentials", lazy=True, cascade="all, delete-orphan")
    )

    __table_args__ = (
        UniqueConstraint("id", "user_id", name="uq_credential_owner"),
    )


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField("Master password", validators=[DataRequired()])
    submit = SubmitField("Sign in")


class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField(
        "Master password",
        validators=[
            DataRequired(),
            Length(min=12, max=128),
        ],
    )
    confirm_password = PasswordField(
        "Confirm password",
        validators=[DataRequired(), EqualTo("password")],
    )
    submit = SubmitField("Create account")


class CredentialForm(FlaskForm):
    site = StringField("Website / service", validators=[DataRequired(), Length(max=200)])
    login_username = StringField("Login username / email", validators=[DataRequired(), Length(max=200)])
    login_password = PasswordField("Password", validators=[DataRequired(), Length(max=256)])
    notes = TextAreaField("Notes", validators=[Length(max=2000)])
    submit = SubmitField("Save credential")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please sign in first.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def current_user():
    user_id = session.get("user_id")
    return db.session.get(User, user_id) if user_id else None


# Deployment uses an in-memory key cache. The browser session contains only
# a random identifier, not the master password or the derived encryption key.
VAULT_KEYS = {}


def get_vault_key(user):
    """Return the user's derived vault key from the server-side memory cache."""
    vault_token = session.get("vault_token")
    key = VAULT_KEYS.get(vault_token)
    if not key:
        raise ValueError("Vault key is not available. Please sign in again.")
    return key


def validate_master_password(password):
    # Suitable policy
    if len(password) < 12:
        return "Master password must contain at least 12 characters."
    if password.lower() == password or password.upper() == password:
        return "Master password must contain both uppercase and lowercase characters."
    if not any(ch.isdigit() for ch in password):
        return "Master password must contain at least one number."
    if not any(not ch.isalnum() for ch in password):
        return "Master password must contain at least one special character."
    return None


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    return response


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("vault"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("vault"))

    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data

        error = validate_master_password(password)
        if error:
            flash(error, "danger")
            return render_template("register.html", form=form)

        if User.query.filter_by(username=username).first():
            flash("That username is already registered.", "danger")
            return render_template("register.html", form=form)

        user = User(
            username=username,
            password_hash=generate_password_hash(password, method="scrypt"),
            encryption_salt=os.urandom(16),
        )
        db.session.add(user)
        db.session.commit()

        flash("Account created. You can now sign in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("vault"))

    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        user = User.query.filter_by(username=username).first()

        if user and user.locked_until and user.locked_until > datetime.utcnow():
            remaining = int((user.locked_until - datetime.utcnow()).total_seconds() / 60) + 1
            flash(f"Account temporarily locked. Try again in about {remaining} minute(s).", "danger")
            return render_template("login.html", form=form)

        valid = user and check_password_hash(user.password_hash, form.password.data)

        if not valid:
            if user:
                user.failed_attempts += 1
                if user.failed_attempts >= 5:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=5)
                    user.failed_attempts = 0
                    flash("Too many failed attempts. Account locked for 5 minutes.", "danger")
                else:
                    flash("Invalid username or password.", "danger")
                db.session.commit()
            else:
                # Same response helps avoid revealing whether a username exists.
                flash("Invalid username or password.", "danger")
            return render_template("login.html", form=form)

        user.failed_attempts = 0
        user.locked_until = None
        db.session.commit()

        session.clear()
        session.permanent = True
        session["user_id"] = user.id
        vault_token = secrets.token_urlsafe(32)
        session["vault_token"] = vault_token
        VAULT_KEYS[vault_token] = derive_encryption_key(
            form.password.data, user.encryption_salt
        )

        return redirect(url_for("vault"))

    return render_template("login.html", form=form)


@app.post("/logout")
@login_required
def logout():
    vault_token = session.get("vault_token")
    if vault_token:
        VAULT_KEYS.pop(vault_token, None)
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("index"))


@app.route("/vault")
@login_required
def vault():
    user = current_user()
    entries = []

    try:
        key = get_vault_key(user)
        for credential in Credential.query.filter_by(user_id=user.id).order_by(Credential.updated_at.desc()):
            try:
                data = decrypt_json(credential.encrypted_data, key)
                entries.append(
                    {
                        "id": credential.id,
                        "site": data.get("site", ""),
                        "login_username": data.get("login_username", ""),
                        "notes": data.get("notes", ""),
                        "updated_at": credential.updated_at,
                    }
                )
            except ValueError:
                app.logger.warning("Could not decrypt credential %s", credential.id)
                entries.append(
                    {
                        "id": credential.id,
                        "site": "[Encrypted entry unavailable]",
                        "login_username": "",
                        "notes": "",
                        "updated_at": credential.updated_at,
                    }
                )
    except Exception:
        flash("The vault could not be opened.", "danger")

    return render_template("vault.html", user=user, entries=entries)


@app.route("/credential/new", methods=["GET", "POST"])
@login_required
def new_credential():
    form = CredentialForm()
    if form.validate_on_submit():
        user = current_user()
        key = get_vault_key(user)

        payload = {
            "site": form.site.data.strip(),
            "login_username": form.login_username.data.strip(),
            "login_password": form.login_password.data,
            "notes": form.notes.data.strip() if form.notes.data else "",
        }

        db.session.add(
            Credential(
                user_id=user.id,
                encrypted_data=encrypt_json(payload, key),
            )
        )
        db.session.commit()

        flash("Credential saved in encrypted form.", "success")
        return redirect(url_for("vault"))

    return render_template("credential_form.html", form=form, title="Add credential")


@app.route("/credential/<int:credential_id>/edit", methods=["GET", "POST"])
@login_required
def edit_credential(credential_id):
    credential = Credential.query.filter_by(
        id=credential_id, user_id=session["user_id"]
    ).first_or_404()

    user = current_user()
    key = get_vault_key(user)

    try:
        data = decrypt_json(credential.encrypted_data, key)
    except ValueError:
        flash("This credential could not be decrypted.", "danger")
        return redirect(url_for("vault"))

    form = CredentialForm(
        site=data.get("site", ""),
        login_username=data.get("login_username", ""),
        login_password=data.get("login_password", ""),
        notes=data.get("notes", ""),
    )

    if form.validate_on_submit():
        payload = {
            "site": form.site.data.strip(),
            "login_username": form.login_username.data.strip(),
            "login_password": form.login_password.data,
            "notes": form.notes.data.strip() if form.notes.data else "",
        }
        credential.encrypted_data = encrypt_json(payload, key)
        credential.updated_at = datetime.utcnow()
        db.session.commit()
        flash("Credential updated and re-encrypted.", "success")
        return redirect(url_for("vault"))

    return render_template("credential_form.html", form=form, title="Edit credential")


@app.post("/credential/<int:credential_id>/delete")
@login_required
def delete_credential(credential_id):
    credential = Credential.query.filter_by(
        id=credential_id, user_id=session["user_id"]
    ).first_or_404()

    db.session.delete(credential)
    db.session.commit()
    flash("Credential deleted.", "success")
    return redirect(url_for("vault"))


@app.route("/credential/<int:credential_id>/view")
@login_required
def view_credential(credential_id):
    credential = Credential.query.filter_by(
        id=credential_id, user_id=session["user_id"]
    ).first_or_404()

    try:
        data = decrypt_json(credential.encrypted_data, get_vault_key(current_user()))
    except ValueError:
        flash("This credential could not be decrypted.", "danger")
        return redirect(url_for("vault"))

    return render_template(
        "credential_view.html",
        credential=credential,
        data=data,
    )


@app.route("/about")
@login_required
def about():
    return render_template("about.html")


@app.cli.command("init-db")
def init_db():
    db.create_all()
    print("Database initialised.")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1")
