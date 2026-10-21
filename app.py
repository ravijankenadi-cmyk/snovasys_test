import os, uuid, hashlib, hmac, json, secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, String, Integer, DateTime, ForeignKey, Text, select, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./trustvault.db")
STORAGE_DIR = Path(os.getenv("TRUSTVAULT_STORAGE", "./private_files")).resolve()
STORAGE_DIR.mkdir(parents=True, exist_ok=True)
JWT_SECRET = os.getenv("TRUSTVAULT_JWT_SECRET")
AUDIT_SECRET = os.getenv("TRUSTVAULT_AUDIT_SECRET")
if not JWT_SECRET or len(JWT_SECRET) < 32:
    raise RuntimeError("Set TRUSTVAULT_JWT_SECRET to a random secret of at least 32 characters.")
if not AUDIT_SECRET or len(AUDIT_SECRET) < 32:
    raise RuntimeError("Set TRUSTVAULT_AUDIT_SECRET to a separate random secret of at least 32 characters.")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
ph = PasswordHasher()
bearer = HTTPBearer(auto_error=False)
app = FastAPI(title="TrustVault API", version="0.1.0")

class Base(DeclarativeBase): pass

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20))  # admin, owner, viewer
    active: Mapped[int] = mapped_column(Integer, default=1)

class Document(Base):
    __tablename__ = "documents"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    category: Mapped[str] = mapped_column(String(100), default="General")
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    storage_key: Mapped[str] = mapped_column(String(80), unique=True)
    sha256: Mapped[str] = mapped_column(String(64))
    size: Mapped[int] = mapped_column(Integer)
    content_type: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class Grant(Base):
    __tablename__ = "grants"
    __table_args__ = (UniqueConstraint("document_id", "user_id", name="uq_doc_user_grant"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    document_id: Mapped[str] = mapped_column(ForeignKey("documents.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    permission: Mapped[str] = mapped_column(String(10))  # read or edit
    granted_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    actor_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    action: Mapped[str] = mapped_column(String(60))
    document_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    target_user_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    outcome: Mapped[str] = mapped_column(String(20))
    details: Mapped[str] = mapped_column(Text, default="{}")
    previous_hash: Mapped[str] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64), unique=True)

Base.metadata.create_all(engine)

def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def now_utc():
    return datetime.now(timezone.utc)

def audit(db: Session, actor_id, action, document_id=None, target_user_id=None, outcome="allowed", details=None):
    previous = db.scalar(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(1))
    prev_hash = previous.event_hash if previous else "GENESIS"
    occurred = now_utc().replace(tzinfo=None).isoformat()
    payload = {
        "occurred_at": occurred, "actor_id": actor_id, "action": action,
        "document_id": document_id, "target_user_id": target_user_id,
        "outcome": outcome, "details": details or {}, "previous_hash": prev_hash
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    event_hash = hmac.new(AUDIT_SECRET.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    db.add(AuditEvent(
        occurred_at=datetime.fromisoformat(occurred), actor_id=actor_id, action=action,
        document_id=document_id, target_user_id=target_user_id, outcome=outcome,
        details=json.dumps(details or {}, sort_keys=True), previous_hash=prev_hash, event_hash=event_hash
    ))
    db.commit()

def get_current_user(creds: HTTPAuthorizationCredentials = Depends(bearer), db: Session = Depends(db_session)):
    if not creds:
        raise HTTPException(401, "Authentication required")
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=["HS256"])
        uid = int(payload["sub"])
    except Exception:
        raise HTTPException(401, "Invalid or expired token")
    user = db.get(User, uid)
    if not user or not user.active:
        raise HTTPException(401, "User inactive or missing")
    return user

def require_role(*roles):
    def dependency(user: User = Depends(get_current_user)):
        if user.role not in roles:
            raise HTTPException(403, "Role not permitted")
        return user
    return dependency

def document_or_404(db: Session, document_id: str):
    doc = db.get(Document, document_id)
    if not doc:
        raise HTTPException(404, "Document not found")
    return doc

def can_read(db: Session, user: User, doc: Document):
    if doc.owner_id == user.id:
        return True
    grant = db.scalar(select(Grant).where(Grant.document_id == doc.id, Grant.user_id == user.id))
    return bool(grant and grant.permission in ("read", "edit"))

def can_edit(db: Session, user: User, doc: Document):
    if doc.owner_id == user.id:
        return True
    grant = db.scalar(select(Grant).where(Grant.document_id == doc.id, Grant.user_id == user.id))
    return bool(grant and grant.permission == "edit")

def allowed_doc(db, user, doc, action):
    ok = can_read(db, user, doc) if action == "read" else can_edit(db, user, doc)
    if not ok:
        audit(db, user.id, action, doc.id, outcome="denied", details={"reason": "missing_document_grant"})
        # Avoid confirming existence to unauthorised users.
        raise HTTPException(404, "Document not found")
    return doc

class LoginBody(BaseModel):
    username: str
    password: str

class GrantBody(BaseModel):
    username: str
    permission: str = Field(pattern="^(read|edit)$")

class MetadataBody(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    category: str = Field(min_length=1, max_length=100)

@app.post("/auth/login")
def login(body: LoginBody, request: Request, db: Session = Depends(db_session)):
    user = db.scalar(select(User).where(User.username == body.username))
    valid = False
    if user and user.active:
        try:
            valid = ph.verify(user.password_hash, body.password)
        except VerifyMismatchError:
            valid = False
        except Exception:
            valid = False
    if not valid:
        # Do not reveal whether username exists.
        audit(db, user.id if user else None, "login", outcome="denied", details={"username": body.username, "ip": request.client.host if request.client else "unknown"})
        raise HTTPException(401, "Invalid username or password")
    token = jwt.encode({"sub": str(user.id), "exp": now_utc() + timedelta(minutes=20)}, JWT_SECRET, algorithm="HS256")
    audit(db, user.id, "login", details={"ip": request.client.host if request.client else "unknown"})
    return {"access_token": token, "token_type": "bearer", "expires_in_seconds": 1200, "role": user.role}

@app.get("/me")
def me(user: User = Depends(get_current_user)):
    return {"id": user.id, "username": user.username, "role": user.role}

@app.post("/documents")
async def upload_document(
    name: str = Form(...), category: str = Form("General"), file: UploadFile = File(...),
    user: User = Depends(require_role("owner")), db: Session = Depends(db_session)
):
    # Allowlist, size cap, and signature checks. Never trust the supplied filename/path.
    allowed = {
        ".pdf": ("application/pdf", b"%PDF-"),
        ".png": ("image/png", b"\x89PNG\r\n\x1a\n"),
        ".jpg": ("image/jpeg", b"\xff\xd8\xff"),
        ".jpeg": ("image/jpeg", b"\xff\xd8\xff"),
        ".txt": ("text/plain", None),
    }
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in allowed:
        audit(db, user.id, "upload", outcome="denied", details={"reason": "extension_not_allowed"})
        raise HTTPException(415, "File type not allowed")
    data = await file.read(10 * 1024 * 1024 + 1)
    if not data or len(data) > 10 * 1024 * 1024:
        audit(db, user.id, "upload", outcome="denied", details={"reason": "size_or_empty"})
        raise HTTPException(413, "File must be between 1 byte and 10 MB")
    expected_type, signature = allowed[suffix]
    if signature and not data.startswith(signature):
        audit(db, user.id, "upload", outcome="denied", details={"reason": "signature_mismatch"})
        raise HTTPException(415, "File content does not match extension")
    if suffix == ".txt":
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(415, "Text file must be UTF-8")
    doc_id, storage_key = str(uuid.uuid4()), secrets.token_hex(32)
    digest = hashlib.sha256(data).hexdigest()
    path = STORAGE_DIR / storage_key
    # Exclusive create avoids overwriting another file.
    with open(path, "xb") as f:
        f.write(data)
    doc = Document(id=doc_id, name=Path(name).name[:255], category=category[:100], owner_id=user.id,
                   storage_key=storage_key, sha256=digest, size=len(data), content_type=expected_type)
    db.add(doc)
    db.commit()
    audit(db, user.id, "upload", doc.id, details={"name": doc.name, "sha256": digest, "size": len(data)})
    return {"id": doc.id, "name": doc.name, "category": doc.category, "sha256": digest, "size": len(data)}

@app.get("/documents")
def search_documents(
    name: Optional[str] = None, owner: Optional[str] = None, category: Optional[str] = None,
    date_from: Optional[str] = None, date_to: Optional[str] = None,
    user: User = Depends(get_current_user), db: Session = Depends(db_session)
):
    query = select(Document)
    # Restrict results to owner documents or explicit grants before applying search filters.
    if user.role != "admin":
        granted_ids = select(Grant.document_id).where(Grant.user_id == user.id)
        query = query.where((Document.owner_id == user.id) | (Document.id.in_(granted_ids)))
    if name:
        query = query.where(Document.name.ilike(f"%{name[:100]}%"))
    if category:
        query = query.where(Document.category.ilike(f"%{category[:100]}%"))
    if owner:
        owner_user = db.scalar(select(User).where(User.username == owner))
        if not owner_user:
            return []
        query = query.where(Document.owner_id == owner_user.id)
    if date_from:
        try: query = query.where(Document.created_at >= datetime.fromisoformat(date_from))
        except ValueError: raise HTTPException(400, "date_from must be ISO format")
    if date_to:
        try: query = query.where(Document.created_at <= datetime.fromisoformat(date_to))
        except ValueError: raise HTTPException(400, "date_to must be ISO format")
    docs = db.scalars(query.order_by(Document.created_at.desc()).limit(200)).all()
    return [{"id": d.id, "name": d.name, "category": d.category, "owner_id": d.owner_id,
             "size": d.size, "created_at": d.created_at.isoformat()} for d in docs]

@app.get("/documents/{document_id}")
def get_document(document_id: str, user: User = Depends(get_current_user), db: Session = Depends(db_session)):
    doc = document_or_404(db, document_id)
    allowed_doc(db, user, doc, "read")
    audit(db, user.id, "metadata_read", doc.id)
    return {"id": doc.id, "name": doc.name, "category": doc.category, "owner_id": doc.owner_id,
            "size": doc.size, "sha256": doc.sha256, "created_at": doc.created_at.isoformat()}

@app.get("/documents/{document_id}/download")
def download_document(document_id: str, user: User = Depends(get_current_user), db: Session = Depends(db_session)):
    doc = document_or_404(db, document_id)
    # Critical security check: every download is authorised on the server at request time.
    allowed_doc(db, user, doc, "read")
    path = STORAGE_DIR / doc.storage_key
    if not path.is_file():
        audit(db, user.id, "download", doc.id, outcome="error", details={"reason": "storage_missing"})
        raise HTTPException(404, "Document content not found")
    audit(db, user.id, "download", doc.id, details={"sha256": doc.sha256, "size": doc.size})
    return StreamingResponse(open(path, "rb"), media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{doc.name.replace(chr(34), "")}"',
                 "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"})

@app.patch("/documents/{document_id}")
def update_metadata(document_id: str, body: MetadataBody, user: User = Depends(get_current_user), db: Session = Depends(db_session)):
    doc = document_or_404(db, document_id)
    allowed_doc(db, user, doc, "edit")
    before = {"name": doc.name, "category": doc.category}
    doc.name, doc.category, doc.updated_at = body.name, body.category, now_utc()
    db.commit()
    audit(db, user.id, "metadata_update", doc.id, details={"before": before, "after": {"name": doc.name, "category": doc.category}})
    return {"id": doc.id, "name": doc.name, "category": doc.category}

@app.post("/documents/{document_id}/grants")
def grant_access(document_id: str, body: GrantBody, user: User = Depends(get_current_user), db: Session = Depends(db_session)):
    doc = document_or_404(db, document_id)
    if doc.owner_id != user.id:
        audit(db, user.id, "grant_access", doc.id, outcome="denied")
        raise HTTPException(404, "Document not found")
    target = db.scalar(select(User).where(User.username == body.username, User.active == 1))
    if not target:
        raise HTTPException(404, "Active user not found")
    if target.id == user.id:
        raise HTTPException(400, "Owner already has full control")
    existing = db.scalar(select(Grant).where(Grant.document_id == doc.id, Grant.user_id == target.id))
    if existing:
        existing.permission, existing.granted_by, existing.created_at = body.permission, user.id, now_utc()
    else:
        db.add(Grant(document_id=doc.id, user_id=target.id, permission=body.permission, granted_by=user.id))
    db.commit()
    audit(db, user.id, "grant_access", doc.id, target.id, details={"permission": body.permission})
    return {"document_id": doc.id, "username": target.username, "permission": body.permission}

@app.delete("/documents/{document_id}/grants/{username}")
def revoke_access(document_id: str, username: str, user: User = Depends(get_current_user), db: Session = Depends(db_session)):
    doc = document_or_404(db, document_id)
    if doc.owner_id != user.id:
        audit(db, user.id, "revoke_access", doc.id, outcome="denied")
        raise HTTPException(404, "Document not found")
    target = db.scalar(select(User).where(User.username == username))
    grant = db.scalar(select(Grant).where(Grant.document_id == doc.id, Grant.user_id == target.id)) if target else None
    if not grant:
        audit(db, user.id, "revoke_access", doc.id, target.id if target else None, outcome="not_found")
        raise HTTPException(404, "Grant not found")
    db.delete(grant)
    db.commit()
    audit(db, user.id, "revoke_access", doc.id, target.id)
    # No presigned/public URLs are issued; future download requests check the grant again.
    return {"revoked": True}

@app.delete("/documents/{document_id}")
def delete_document(document_id: str, user: User = Depends(get_current_user), db: Session = Depends(db_session)):
    doc = document_or_404(db, document_id)
    if doc.owner_id != user.id:
        audit(db, user.id, "delete_document", doc.id, outcome="denied")
        raise HTTPException(404, "Document not found")
    snapshot = {"name": doc.name, "sha256": doc.sha256}
    path = STORAGE_DIR / doc.storage_key
    # Record the event before destructive action; production should use a transactional outbox.
    audit(db, user.id, "delete_document", doc.id, details=snapshot)
    if path.exists():
        path.unlink()
    db.query(Grant).filter(Grant.document_id == doc.id).delete(synchronize_session=False)
    db.delete(doc)
    db.commit()
    return {"deleted": True}

@app.get("/admin/audit")
def admin_audit(limit: int = 100, user: User = Depends(require_role("admin")), db: Session = Depends(db_session)):
    events = db.scalars(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(max(1, min(limit, 500)))).all()
    return [{"id": e.id, "occurred_at": e.occurred_at.isoformat(), "actor_id": e.actor_id,
             "action": e.action, "document_id": e.document_id, "target_user_id": e.target_user_id,
             "outcome": e.outcome, "details": json.loads(e.details), "previous_hash": e.previous_hash,
             "event_hash": e.event_hash} for e in events]

@app.get("/admin/audit/verify")
def verify_audit(user: User = Depends(require_role("admin")), db: Session = Depends(db_session)):
    events = db.scalars(select(AuditEvent).order_by(AuditEvent.id.asc())).all()
    prev = "GENESIS"
    for e in events:
        payload = {
            "occurred_at": e.occurred_at.isoformat(), "actor_id": e.actor_id, "action": e.action,
            "document_id": e.document_id, "target_user_id": e.target_user_id,
            "outcome": e.outcome, "details": json.loads(e.details), "previous_hash": prev
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        expected = hmac.new(AUDIT_SECRET.encode(), canonical.encode(), hashlib.sha256).hexdigest()
        if e.previous_hash != prev or not hmac.compare_digest(expected, e.event_hash):
            return {"valid": False, "failed_event_id": e.id}
        prev = e.event_hash
    return {"valid": True, "events_checked": len(events)}

# Development-only bootstrap. Set TRUSTVAULT_BOOTSTRAP=1 explicitly.
# Remove/disable this route in production and provision accounts out-of-band.
@app.post("/dev/bootstrap")
def bootstrap(db: Session = Depends(db_session)):
    if os.getenv("TRUSTVAULT_BOOTSTRAP") != "1":
        raise HTTPException(404, "Not found")
    if db.scalar(select(User.id).limit(1)):
        raise HTTPException(409, "Users already exist")
    seed = [
        ("admin", "AdminPass-ChangeMe-2026!", "admin"),
        ("owner", "OwnerPass-ChangeMe-2026!", "owner"),
        ("viewer", "ViewerPass-ChangeMe-2026!", "viewer"),
    ]
    for username, password, role in seed:
        db.add(User(username=username, password_hash=ph.hash(password), role=role, active=1))
    db.commit()
    return {"created": ["admin", "owner", "viewer"], "warning": "Development credentials only; change them immediately."}
