import os, uuid, hashlib, json
from datetime import datetime, timezone
from pathlib import Path
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, send_file, abort
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, FileField, SelectField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

load_dotenv()
BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "storage" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-only-change-this-secret-before-deployment")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'instance' / 'trustvault.db'}")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
app.config["UPLOAD_DIR"] = str(UPLOAD_DIR)
Path(BASE_DIR / "instance").mkdir(exist_ok=True)

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to continue."

ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "txt", "png", "jpg", "jpeg", "csv", "xlsx", "pptx", "zip"}

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    original_name = db.Column(db.String(255), nullable=False)
    stored_name = db.Column(db.String(80), unique=True, nullable=False)
    title = db.Column(db.String(160), nullable=False)
    size_bytes = db.Column(db.Integer, nullable=False)
    sha256 = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    owner = db.relationship("User", backref="owned_documents")

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey("document.id"), nullable=False, index=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    role = db.Column(db.String(10), nullable=False, default="viewer")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    document = db.relationship("Document", backref=db.backref("permissions", cascade="all, delete-orphan"))
    recipient = db.relationship("User", backref="received_permissions")
    __table_args__ = (db.UniqueConstraint("document_id", "recipient_id", name="unique_document_recipient"),)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    actor_email = db.Column(db.String(255), nullable=False)
    action = db.Column(db.String(80), nullable=False)
    document_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.Text, nullable=False, default="{}")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    previous_hash = db.Column(db.String(64), nullable=False)
    event_hash = db.Column(db.String(64), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

class RegisterForm(FlaskForm):
    name = StringField("Full name", validators=[DataRequired(), Length(min=2, max=100)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=255)])
    password = PasswordField("Password (at least 8 characters)", validators=[DataRequired(), Length(min=8, max=128)])
    confirm_password = PasswordField("Confirm password", validators=[DataRequired(), EqualTo("password", message="Passwords must match.")])
    submit = SubmitField("Create account")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign in")

class UploadForm(FlaskForm):
    title = StringField("Document title", validators=[DataRequired(), Length(min=1, max=160)])
    file = FileField("Choose a document", validators=[DataRequired()])
    submit = SubmitField("Upload document")

class ShareForm(FlaskForm):
    email = StringField("Share with registered user (email)", validators=[DataRequired(), Email()])
    role = SelectField("Permission", choices=[("viewer", "Viewer — can download"), ("editor", "Editor — can download and manage sharing")], validators=[DataRequired()])
    submit = SubmitField("Share document")

def utc_iso(dt):
    # SQLite may return naive datetimes even when timezone=True was requested.
    # Treat stored naive timestamps as UTC so audit hashes verify consistently.
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def append_audit(action, document_id=None, details=None, actor=None):
    actor = actor if actor is not None else (current_user if current_user.is_authenticated else None)
    last = db.session.query(AuditLog).order_by(AuditLog.id.desc()).first()
    previous = last.event_hash if last else "GENESIS"
    email = actor.email if actor else "system"
    actor_id = actor.id if actor else None
    timestamp = datetime.now(timezone.utc)
    details_json = json.dumps(details or {}, sort_keys=True, separators=(",", ":"))
    payload = json.dumps({
        "actor_email": email, "action": action, "document_id": document_id,
        "details": json.loads(details_json), "created_at": utc_iso(timestamp),
        "previous_hash": previous
    }, sort_keys=True, separators=(",", ":"))
    event_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    db.session.add(AuditLog(actor_id=actor_id, actor_email=email, action=action,
        document_id=document_id, details=details_json, created_at=timestamp,
        previous_hash=previous, event_hash=event_hash))

def can_access(doc, user):
    if doc.owner_id == user.id:
        return "owner"
    perm = Permission.query.filter_by(document_id=doc.id, recipient_id=user.id).first()
    return perm.role if perm else None

def can_manage_sharing(doc, user):
    role = can_access(doc, user)
    return role in ("owner", "editor")

@app.context_processor
def inject_globals():
    return {"app_name": "TrustVault"}

@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        if User.query.filter_by(email=email).first():
            flash("An account with that email already exists.", "error")
        else:
            user = User(name=form.name.data.strip(), email=email)
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.flush()
            append_audit("account_registered", details={"email": email}, actor=user)
            db.session.commit()
            login_user(user)
            flash("Welcome to TrustVault. Your account is ready.", "success")
            return redirect(url_for("dashboard"))
    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.strip().lower()).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            append_audit("login_success")
            db.session.commit()
            return redirect(url_for("dashboard"))
        flash("Email or password is incorrect.", "error")
    return render_template("login.html", form=form)

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    append_audit("logout")
    db.session.commit()
    logout_user()
    flash("You have signed out.", "success")
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    owned = Document.query.filter_by(owner_id=current_user.id).order_by(Document.created_at.desc()).all()
    received = Permission.query.filter_by(recipient_id=current_user.id).order_by(Permission.created_at.desc()).all()
    recent = AuditLog.query.filter_by(actor_id=current_user.id).order_by(AuditLog.id.desc()).limit(6).all()
    return render_template("dashboard.html", owned=owned, received=received, recent=recent)

@app.route("/documents")
@login_required
def documents():
    owned = Document.query.filter_by(owner_id=current_user.id).order_by(Document.created_at.desc()).all()
    shared = Permission.query.filter_by(recipient_id=current_user.id).order_by(Permission.created_at.desc()).all()
    return render_template("documents.html", owned=owned, shared=shared)

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    form = UploadForm()
    if form.validate_on_submit():
        uploaded = form.file.data
        clean_name = secure_filename(uploaded.filename or "")
        if not clean_name or not allowed_file(clean_name):
            flash("Unsupported file type. Allowed: PDF, Office documents, TXT, images, CSV and ZIP.", "error")
            return render_template("upload.html", form=form)
        stored_name = uuid.uuid4().hex
        destination = Path(app.config["UPLOAD_DIR"]) / stored_name
        uploaded.save(destination)
        digest = sha256_file(destination)
        doc = Document(owner_id=current_user.id, original_name=clean_name,
            stored_name=stored_name, title=form.title.data.strip(),
            size_bytes=destination.stat().st_size, sha256=digest)
        db.session.add(doc)
        db.session.flush()
        append_audit("document_uploaded", doc.id, {"title": doc.title, "sha256": digest})
        db.session.commit()
        flash("Document uploaded successfully.", "success")
        return redirect(url_for("documents"))
    return render_template("upload.html", form=form)

@app.route("/documents/<int:doc_id>/download")
@login_required
def download(doc_id):
    doc = db.session.get(Document, doc_id)
    if not doc or not can_access(doc, current_user):
        abort(404)
    path = Path(app.config["UPLOAD_DIR"]) / doc.stored_name
    if not path.is_file():
        abort(404)
    current_hash = sha256_file(path)
    if current_hash != doc.sha256:
        append_audit("document_integrity_mismatch", doc.id, {"expected": doc.sha256, "actual": current_hash})
        db.session.commit()
        flash("Integrity check failed. The file was not downloaded.", "error")
        return redirect(url_for("documents"))
    append_audit("document_downloaded", doc.id, {"title": doc.title})
    db.session.commit()
    return send_file(path, as_attachment=True, download_name=doc.original_name)

@app.route("/documents/<int:doc_id>/delete", methods=["POST"])
@login_required
def delete_document(doc_id):
    doc = db.session.get(Document, doc_id)
    if not doc or doc.owner_id != current_user.id:
        abort(404)
    path = Path(app.config["UPLOAD_DIR"]) / doc.stored_name
    append_audit("document_deleted", doc.id, {"title": doc.title})
    if path.exists():
        path.unlink()
    db.session.delete(doc)
    db.session.commit()
    flash("Document deleted.", "success")
    return redirect(url_for("documents"))

@app.route("/documents/<int:doc_id>/share", methods=["GET", "POST"])
@login_required
def share_document(doc_id):
    doc = db.session.get(Document, doc_id)
    if not doc or not can_manage_sharing(doc, current_user):
        abort(404)
    form = ShareForm()
    if form.validate_on_submit():
        recipient = User.query.filter_by(email=form.email.data.strip().lower()).first()
        if not recipient:
            flash("That email is not registered. Ask the recipient to create a TrustVault account first.", "error")
        elif recipient.id == doc.owner_id:
            flash("You cannot share a document with its owner.", "error")
        else:
            perm = Permission.query.filter_by(document_id=doc.id, recipient_id=recipient.id).first()
            if perm:
                perm.role = form.role.data
            else:
                db.session.add(Permission(document_id=doc.id, recipient_id=recipient.id, role=form.role.data))
            append_audit("document_shared", doc.id, {"recipient": recipient.email, "role": form.role.data})
            db.session.commit()
            flash(f"Document shared with {recipient.email}.", "success")
            return redirect(url_for("share_document", doc_id=doc.id))
    permissions = Permission.query.filter_by(document_id=doc.id).all()
    return render_template("share.html", doc=doc, form=form, permissions=permissions)

@app.route("/documents/<int:doc_id>/revoke/<int:permission_id>", methods=["POST"])
@login_required
def revoke_share(doc_id, permission_id):
    doc = db.session.get(Document, doc_id)
    perm = db.session.get(Permission, permission_id)
    if not doc or not can_manage_sharing(doc, current_user) or not perm or perm.document_id != doc.id:
        abort(404)
    recipient_email = perm.recipient.email
    db.session.delete(perm)
    append_audit("document_access_revoked", doc.id, {"recipient": recipient_email})
    db.session.commit()
    flash("Access revoked.", "success")
    return redirect(url_for("share_document", doc_id=doc.id))

@app.route("/audit")
@login_required
def audit():
    # Show logs involving the current user or documents they own/share.
    owned_ids = [d.id for d in Document.query.filter_by(owner_id=current_user.id).all()]
    shared_ids = [p.document_id for p in Permission.query.filter_by(recipient_id=current_user.id).all()]
    relevant_ids = set(owned_ids + shared_ids)
    logs = AuditLog.query.filter(
        db.or_(AuditLog.actor_id == current_user.id, AuditLog.document_id.in_(relevant_ids) if relevant_ids else db.false())
    ).order_by(AuditLog.id.desc()).limit(200).all()
    valid, checked, error_id = verify_audit_chain()
    return render_template("audit.html", logs=logs, chain_valid=valid, checked=checked, error_id=error_id)

def verify_audit_chain():
    rows = AuditLog.query.order_by(AuditLog.id.asc()).all()
    previous = "GENESIS"
    for row in rows:
        payload = json.dumps({
            "actor_email": row.actor_email, "action": row.action,
            "document_id": row.document_id, "details": json.loads(row.details or "{}"),
            "created_at": utc_iso(row.created_at), "previous_hash": row.previous_hash
        }, sort_keys=True, separators=(",", ":"))
        expected = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        if row.previous_hash != previous or row.event_hash != expected:
            return False, len(rows), row.id
        previous = row.event_hash
    return True, len(rows), None

@app.route("/audit/verify", methods=["POST"])
@login_required
def verify_audit_route():
    valid, checked, error_id = verify_audit_chain()
    append_audit("audit_chain_verified", details={"valid": valid, "checked": checked, "error_id": error_id})
    db.session.commit()
    if valid:
        flash(f"Audit chain verified: {checked} events checked.", "success")
    else:
        flash(f"Audit chain verification failed at event #{error_id}.", "error")
    return redirect(url_for("audit"))

@app.errorhandler(413)
def too_large(_error):
    flash("File is too large. Maximum upload size is 16 MB.", "error")
    return redirect(url_for("upload"))

@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, message="That page or resource was not found."), 404

@app.errorhandler(500)
def server_error(_error):
    db.session.rollback()
    return render_template("error.html", code=500, message="Something went wrong. Please try again."), 500

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "0") == "1")
