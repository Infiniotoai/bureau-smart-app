from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, APIRouter, HTTPException, Request, UploadFile, File, Depends, Response
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
import os
import logging
import uuid
import bcrypt
import jwt
import base64
import secrets
import requests
import smtplib
import random
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone, timedelta
from emergentintegrations.llm.chat import LlmChat, UserMessage

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

import json

ROOT_DIR = Path(__file__).parent


def parse_ai_json(response_text: str) -> dict:
    """Extract and parse JSON from an AI model response, handling code fences."""
    text = response_text.strip()
    if text.startswith("```json"):
        text = text[7:]
    if text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    return json.loads(text.strip())


def require_subscription(user: dict):
    """Raise 403 if the user is not subscribed and not an admin."""
    if user.get("subscription_status") != "active" and user.get("role") != "admin":
        raise HTTPException(
            status_code=403,
            detail="Diese Funktion ist nur fur Abonnenten verfugbar. Bitte upgraden Sie Ihr Konto."
        )

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Configuration
JWT_ALGORITHM = "HS256"

def get_jwt_secret() -> str:
    return os.environ.get("JWT_SECRET", "fallback-secret-change-this")

# Object Storage Configuration
STORAGE_URL = "https://integrations.emergentagent.com/objstore/api/v1/storage"
EMERGENT_KEY = os.environ.get("EMERGENT_LLM_KEY")
APP_NAME = "bureaucracy-engine"
storage_key = None

def init_storage():
    global storage_key
    if storage_key:
        return storage_key
    try:
        resp = requests.post(f"{STORAGE_URL}/init", json={"emergent_key": EMERGENT_KEY}, timeout=30)
        resp.raise_for_status()
        storage_key = resp.json()["storage_key"]
        logger.info("Storage initialized successfully")
        return storage_key
    except Exception as e:
        logger.error(f"Storage init failed: {e}")
        raise

def put_object(path: str, data: bytes, content_type: str) -> dict:
    key = init_storage()
    resp = requests.put(
        f"{STORAGE_URL}/objects/{path}",
        headers={"X-Storage-Key": key, "Content-Type": content_type},
        data=data, timeout=120
    )
    resp.raise_for_status()
    return resp.json()

def get_object(path: str) -> tuple:
    key = init_storage()
    resp = requests.get(
        f"{STORAGE_URL}/objects/{path}",
        headers={"X-Storage-Key": key}, timeout=60
    )
    resp.raise_for_status()
    return resp.content, resp.headers.get("Content-Type", "application/octet-stream")

# Password hashing
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))

# JWT Token Management
def create_access_token(user_id: str, email: str) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "exp": datetime.now(timezone.utc) + timedelta(hours=24),
        "type": "access"
    }
    return jwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)

def create_refresh_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(days=30),
        "type": "refresh"
    }
    return jwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)

# Auth helper
async def get_current_user(request: Request) -> dict:
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if not token:
        raise HTTPException(status_code=401, detail="Nicht authentifiziert")
    try:
        payload = jwt.decode(token, get_jwt_secret(), algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Ungültiger Token-Typ")
        user = await db.users.find_one({"_id": ObjectId(payload["sub"])})
        if not user:
            raise HTTPException(status_code=401, detail="Benutzer nicht gefunden")
        user["_id"] = str(user["_id"])
        user.pop("password_hash", None)
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token abgelaufen")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Ungültiger Token")

# Create the main app
app = FastAPI(title="Bureaucracy Intelligence Engine")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Pydantic Models
class UserRegister(BaseModel):
    email: EmailStr
    password: str
    name: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: str
    email: str
    name: str
    role: str
    subscription_status: str
    created_at: str

class DocumentAnalysis(BaseModel):
    summary: str
    action_needed: bool
    deadline: Optional[str] = None
    amount_due: Optional[str] = None
    sender: str
    priority: str
    user_options: List[Dict[str, str]]
    explanation_easy: str

class DocumentResponse(BaseModel):
    id: str
    user_id: str
    filename: str
    file_type: str
    storage_path: str
    analysis: Optional[Dict[str, Any]] = None
    status: str
    created_at: str

class CheckoutRequest(BaseModel):
    origin_url: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class VerifyResetCodeRequest(BaseModel):
    email: EmailStr
    code: str
    new_password: str

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

def send_email(to_email: str, subject: str, html_body: str):
    """Send email via SMTP"""
    smtp_host = os.environ.get("SMTP_HOST")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER")
    smtp_pass = os.environ.get("SMTP_PASS")
    smtp_from = os.environ.get("SMTP_FROM", smtp_user)
    
    if not all([smtp_host, smtp_user, smtp_pass]):
        logger.error("SMTP not configured")
        raise Exception("SMTP not configured")
    
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = smtp_from
    msg["To"] = to_email
    msg.attach(MIMEText(html_body, "html"))
    
    try:
        server = smtplib.SMTP(smtp_host, smtp_port)
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(smtp_user, smtp_pass)
        server.sendmail(smtp_user, to_email, msg.as_string())
        server.quit()
        logger.info(f"Email sent to {to_email}")
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        raise

# Subscription packages
SUBSCRIPTION_PRICE = 2.99

# Auth Endpoints
@api_router.post("/auth/register")
async def register(user: UserRegister, response: Response):
    email = user.email.lower()
    existing = await db.users.find_one({"email": email})
    if existing:
        raise HTTPException(status_code=400, detail="E-Mail bereits registriert")
    
    hashed = hash_password(user.password)
    user_doc = {
        "email": email,
        "password_hash": hashed,
        "name": user.name,
        "role": "user",
        "subscription_status": "inactive",
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    result = await db.users.insert_one(user_doc)
    user_id = str(result.inserted_id)
    
    access_token = create_access_token(user_id, email)
    refresh_token = create_refresh_token(user_id)
    
    response.set_cookie(key="access_token", value=access_token, httponly=True, secure=True, samesite="none", max_age=86400, path="/")
    response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, secure=True, samesite="none", max_age=2592000, path="/")
    
    return {
        "id": user_id,
        "email": email,
        "name": user.name,
        "role": "user",
        "subscription_status": "inactive",
        "created_at": user_doc["created_at"]
    }

@api_router.post("/auth/login")
async def login(user: UserLogin, request: Request, response: Response):
    email = user.email.lower()
    ip = request.client.host
    identifier = f"{ip}:{email}"
    
    # Check brute force
    attempts = await db.login_attempts.find_one({"identifier": identifier})
    if attempts and attempts.get("count", 0) >= 5:
        lockout_time = attempts.get("last_attempt")
        if lockout_time:
            lockout_until = datetime.fromisoformat(lockout_time) + timedelta(minutes=15)
            if datetime.now(timezone.utc) < lockout_until:
                raise HTTPException(status_code=429, detail="Zu viele Anmeldeversuche. Bitte warten Sie 15 Minuten.")
            else:
                await db.login_attempts.delete_one({"identifier": identifier})
    
    db_user = await db.users.find_one({"email": email})
    if not db_user or not verify_password(user.password, db_user["password_hash"]):
        await db.login_attempts.update_one(
            {"identifier": identifier},
            {"$inc": {"count": 1}, "$set": {"last_attempt": datetime.now(timezone.utc).isoformat()}},
            upsert=True
        )
        raise HTTPException(status_code=401, detail="Ungültige Anmeldedaten")
    
    # Clear attempts on success
    await db.login_attempts.delete_one({"identifier": identifier})
    
    user_id = str(db_user["_id"])
    access_token = create_access_token(user_id, email)
    refresh_token = create_refresh_token(user_id)
    
    response.set_cookie(key="access_token", value=access_token, httponly=True, secure=True, samesite="none", max_age=86400, path="/")
    response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, secure=True, samesite="none", max_age=2592000, path="/")
    
    return {
        "id": user_id,
        "email": db_user["email"],
        "name": db_user["name"],
        "role": db_user.get("role", "user"),
        "subscription_status": db_user.get("subscription_status", "inactive"),
        "created_at": db_user["created_at"]
    }

@api_router.post("/auth/logout")
async def logout(response: Response):
    response.delete_cookie(key="access_token", path="/")
    response.delete_cookie(key="refresh_token", path="/")
    return {"message": "Erfolgreich abgemeldet"}

@api_router.get("/auth/me")
async def get_me(request: Request):
    user = await get_current_user(request)
    return user

@api_router.post("/auth/refresh")
async def refresh_token(request: Request, response: Response):
    refresh = request.cookies.get("refresh_token")
    if not refresh:
        raise HTTPException(status_code=401, detail="Kein Refresh-Token")
    try:
        payload = jwt.decode(refresh, get_jwt_secret(), algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Ungültiger Token-Typ")
        
        user = await db.users.find_one({"_id": ObjectId(payload["sub"])})
        if not user:
            raise HTTPException(status_code=401, detail="Benutzer nicht gefunden")
        
        access_token = create_access_token(str(user["_id"]), user["email"])
        response.set_cookie(key="access_token", value=access_token, httponly=True, secure=True, samesite="none", max_age=86400, path="/")
        return {"message": "Token aktualisiert"}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh-Token abgelaufen")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Ungültiger Token")

@api_router.post("/auth/forgot-password")
async def forgot_password(req: ForgotPasswordRequest):
    email = req.email.lower()
    user = await db.users.find_one({"email": email})
    
    # Always return success (don't reveal if email exists)
    if not user:
        return {"message": "Code gesendet", "success": True}
    
    # Generate 6-digit code
    code = str(random.randint(100000, 999999))
    
    # Store code in DB with 15 min expiry
    await db.password_reset_codes.delete_many({"email": email})
    await db.password_reset_codes.insert_one({
        "email": email,
        "code": code,
        "user_id": str(user["_id"]),
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat(),
        "used": False,
        "attempts": 0
    })
    
    # Send email with code
    try:
        html_body = f"""
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 480px; margin: 0 auto; padding: 40px 20px;">
            <div style="text-align: center; margin-bottom: 32px;">
                <div style="display: inline-block; background: linear-gradient(135deg, #7c3aed, #06b6d4); border-radius: 16px; padding: 12px 16px;">
                    <span style="color: white; font-size: 24px; font-weight: bold;">BureauSmart</span>
                </div>
            </div>
            <h2 style="color: #1f2937; text-align: center; margin-bottom: 8px;">Passwort zurucksetzen</h2>
            <p style="color: #6b7280; text-align: center; margin-bottom: 32px;">Verwenden Sie diesen Code, um Ihr Passwort zuruckzusetzen:</p>
            <div style="background: linear-gradient(135deg, #f5f3ff, #ecfeff); border: 2px solid #c4b5fd; border-radius: 16px; padding: 24px; text-align: center; margin-bottom: 24px;">
                <span style="font-size: 36px; font-weight: 800; letter-spacing: 8px; color: #7c3aed;">{code}</span>
            </div>
            <p style="color: #9ca3af; text-align: center; font-size: 14px;">Dieser Code ist 15 Minuten gultig.</p>
            <p style="color: #9ca3af; text-align: center; font-size: 14px;">Falls Sie diese Anfrage nicht gestellt haben, ignorieren Sie diese E-Mail.</p>
        </div>
        """
        send_email(email, "BureauSmart - Passwort zurucksetzen", html_body)
    except Exception as e:
        logger.error(f"Failed to send reset email: {e}")
        # Don't reveal email sending failure to user
    
    return {"message": "Code gesendet", "success": True}

@api_router.post("/auth/verify-reset-code")
async def verify_reset_code(req: VerifyResetCodeRequest):
    email = req.email.lower()
    
    code_doc = await db.password_reset_codes.find_one({"email": email, "used": False})
    if not code_doc:
        raise HTTPException(status_code=400, detail="Kein gultiger Code vorhanden. Bitte fordern Sie einen neuen an.")
    
    # Check max attempts
    if code_doc.get("attempts", 0) >= 5:
        await db.password_reset_codes.update_one({"_id": code_doc["_id"]}, {"$set": {"used": True}})
        raise HTTPException(status_code=429, detail="Zu viele Versuche. Bitte fordern Sie einen neuen Code an.")
    
    # Check expiry
    expires_at = datetime.fromisoformat(code_doc["expires_at"].replace("+00:00", ""))
    if datetime.now(timezone.utc).replace(tzinfo=None) > expires_at:
        raise HTTPException(status_code=400, detail="Code abgelaufen. Bitte fordern Sie einen neuen an.")
    
    # Check code
    if code_doc["code"] != req.code.strip():
        await db.password_reset_codes.update_one(
            {"_id": code_doc["_id"]},
            {"$inc": {"attempts": 1}}
        )
        remaining = 5 - code_doc.get("attempts", 0) - 1
        raise HTTPException(status_code=400, detail=f"Falscher Code. Noch {remaining} Versuche ubrig.")
    
    # Validate password
    if len(req.new_password) < 6:
        raise HTTPException(status_code=400, detail="Passwort muss mindestens 6 Zeichen lang sein.")
    
    # Reset password
    hashed = hash_password(req.new_password)
    await db.users.update_one({"_id": ObjectId(code_doc["user_id"])}, {"$set": {"password_hash": hashed}})
    await db.password_reset_codes.update_one({"_id": code_doc["_id"]}, {"$set": {"used": True}})
    
    return {"message": "Passwort erfolgreich geandert", "success": True}

@api_router.post("/auth/reset-password")
async def reset_password(req: ResetPasswordRequest):
    token_doc = await db.password_reset_tokens.find_one({"token": req.token, "used": False})
    if not token_doc:
        raise HTTPException(status_code=400, detail="Ungültiger oder abgelaufener Token")
    
    if datetime.fromisoformat(str(token_doc["expires_at"]).replace("+00:00", "")) < datetime.now(timezone.utc).replace(tzinfo=None):
        raise HTTPException(status_code=400, detail="Token abgelaufen")
    
    hashed = hash_password(req.new_password)
    await db.users.update_one({"_id": ObjectId(token_doc["user_id"])}, {"$set": {"password_hash": hashed}})
    await db.password_reset_tokens.update_one({"token": req.token}, {"$set": {"used": True}})
    
    return {"message": "Passwort erfolgreich geändert"}

# Document Endpoints
@api_router.post("/documents/upload")
async def upload_document(request: Request, file: UploadFile = File(...)):
    user = await get_current_user(request)
    
    # Check subscription
    if user.get("subscription_status") != "active" and user.get("role") != "admin":
        # Allow 1 free analysis
        doc_count = await db.documents.count_documents({"user_id": user["_id"]})
        if doc_count >= 1:
            raise HTTPException(status_code=403, detail="Abo erforderlich für weitere Analysen")
    
    allowed_types = ["image/jpeg", "image/png", "image/webp", "application/pdf"]
    if file.content_type not in allowed_types:
        raise HTTPException(status_code=400, detail="Ungültiger Dateityp. Erlaubt: JPG, PNG, WebP, PDF")
    
    ext = file.filename.split(".")[-1] if "." in file.filename else "bin"
    file_id = str(uuid.uuid4())
    path = f"{APP_NAME}/uploads/{user['_id']}/{file_id}.{ext}"
    
    data = await file.read()
    try:
        result = put_object(path, data, file.content_type)
    except Exception as e:
        logger.error(f"Upload failed: {e}")
        raise HTTPException(status_code=500, detail="Datei-Upload fehlgeschlagen")
    
    doc = {
        "id": file_id,
        "user_id": user["_id"],
        "filename": file.filename,
        "file_type": file.content_type,
        "storage_path": result["path"],
        "analysis": None,
        "status": "uploaded",
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.documents.insert_one(doc)
    
    return {"id": file_id, "filename": file.filename, "status": "uploaded"}

@api_router.post("/documents/{doc_id}/analyze")
async def analyze_document(doc_id: str, request: Request):
    user = await get_current_user(request)
    
    doc = await db.documents.find_one({"id": doc_id, "user_id": user["_id"]}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Dokument nicht gefunden")
    
    try:
        # Get file from storage
        file_data, content_type = get_object(doc["storage_path"])
        
        # Convert to base64 for AI
        file_base64 = base64.b64encode(file_data).decode("utf-8")
        
        # Initialize Gemini chat with multilingual support
        chat = LlmChat(
            api_key=EMERGENT_KEY,
            session_id=f"doc-analysis-{doc_id}",
            system_message="""Du bist der "Bureaucracy Intelligence Engine". Deine Aufgabe ist es, Dokumente aus ALLEN SPRACHEN zu analysieren und für den Nutzer in einfache, handlungsorientierte Daten zu übersetzen.

WICHTIG: 
- Das Dokument kann in JEDER SPRACHE sein (Deutsch, Englisch, Französisch, etc.)
- ALLE deine Antworten müssen auf DEUTSCH sein
- Erkenne die Originalsprache und übersetze den Inhalt

Analyse-Schritte:
1. Erkenne die Sprache des Dokuments
2. Identifiziere den Absender und den Kernzweck des Schreibens
3. Bestimme die Dringlichkeit (Muss der User sofort handeln?)
4. Extrahiere alle harten Fakten (Termine, Beträge, Referenznummern)
5. Entwirf eine Strategie, wie der Nutzer am besten reagiert

Du MUSST immer mit einem gültigen JSON-Objekt antworten. Kein anderer Text ist erlaubt.

Ausgabe-Format (Strenges JSON):
{
  "summary": "Ein Satz auf Deutsch, der erklärt, was passiert ist.",
  "action_needed": true oder false,
  "deadline": "YYYY-MM-DD (oder null falls kein Datum)",
  "amount_due": "Betrag mit Währung (oder null)",
  "sender": "Name der Behörde/Firma",
  "priority": "Low/Medium/High/Urgent",
  "original_language": "Die erkannte Sprache des Dokuments",
  "user_options": [
    {"label": "Zahlen/Akzeptieren", "draft": "Ein kurzer Textentwurf für die Antwort auf Deutsch."},
    {"label": "Widerspruch einlegen", "draft": "Ein formaler Entwurf für einen Widerspruch auf Deutsch."},
    {"label": "Frage stellen", "draft": "Ein Entwurf auf Deutsch, um mehr Informationen zu erbitten."}
  ],
  "explanation_easy": "Erkläre auf Deutsch in einfacher Sprache (wie einem 12-Jährigen), was dieses Dokument bedeutet."
}"""
        ).with_model("gemini", "gemini-3-flash-preview")
        
        # Create message with image/PDF
        if "pdf" in content_type.lower():
            user_message = UserMessage(
                text=f"Analysiere dieses PDF-Dokument. Das Dokument kann in jeder Sprache sein - erkenne die Sprache und analysiere es. Antworte immer auf Deutsch. Dateiname: {doc['filename']}. Das Dokument ist als Base64 kodiert: {file_base64[:8000]}... (gekürzt). Bitte analysiere es basierend auf dem sichtbaren Text.",
            )
        else:
            user_message = UserMessage(
                text=f"Analysiere dieses Bild eines Dokuments. Das Dokument kann in jeder Sprache sein - erkenne die Sprache und analysiere es. Antworte immer auf Deutsch. Dateiname: {doc['filename']}",
                image_url=f"data:{content_type};base64,{file_base64}"
            )
        
        # Get AI response
        response = await chat.send_message(user_message)
        
        # Parse JSON from response
        try:
            analysis = parse_ai_json(response)
        except json.JSONDecodeError:
            # Create fallback analysis
            analysis = {
                "summary": "Dokument wurde hochgeladen, automatische Analyse nicht möglich.",
                "action_needed": False,
                "deadline": None,
                "amount_due": None,
                "sender": "Unbekannt",
                "priority": "Medium",
                "original_language": "Unbekannt",
                "user_options": [
                    {"label": "Manuell prüfen", "draft": "Bitte prüfen Sie das Dokument manuell."}
                ],
                "explanation_easy": "Das Dokument konnte nicht automatisch analysiert werden. Bitte schauen Sie es sich selbst an."
            }
        
        # Update document
        await db.documents.update_one(
            {"id": doc_id},
            {"$set": {"analysis": analysis, "status": "analyzed"}}
        )
        
        return {"id": doc_id, "analysis": analysis, "status": "analyzed"}
        
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analyse fehlgeschlagen: {str(e)}")

@api_router.get("/documents")
async def get_documents(request: Request, search: Optional[str] = None):
    user = await get_current_user(request)
    
    query = {"user_id": user["_id"]}
    if search:
        query["$or"] = [
            {"filename": {"$regex": search, "$options": "i"}},
            {"analysis.sender": {"$regex": search, "$options": "i"}},
            {"analysis.summary": {"$regex": search, "$options": "i"}}
        ]
    
    docs = await db.documents.find(query, {"_id": 0}).sort("created_at", -1).to_list(100)
    return docs

@api_router.get("/documents/{doc_id}")
async def get_document(doc_id: str, request: Request):
    user = await get_current_user(request)
    
    doc = await db.documents.find_one({"id": doc_id, "user_id": user["_id"]}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Dokument nicht gefunden")
    return doc

@api_router.delete("/documents/{doc_id}")
async def delete_document(doc_id: str, request: Request):
    user = await get_current_user(request)
    
    result = await db.documents.delete_one({"id": doc_id, "user_id": user["_id"]})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Dokument nicht gefunden")
    return {"message": "Dokument gelöscht"}

# Language mapping for translation
LANG_MAP = {
    "de": "Deutsch", "en": "English", "fr": "Français", "es": "Español",
    "it": "Italiano", "nl": "Nederlands", "pl": "Polski", "tr": "Türkçe",
    "pt": "Português", "ru": "Русский", "ar": "العربية", "zh": "中文",
    "ja": "日本語", "ko": "한국어"
}

class TranslateAnalysisRequest(BaseModel):
    target_language: str = "de"

@api_router.post("/documents/{doc_id}/translate-analysis")
async def translate_analysis(doc_id: str, req: TranslateAnalysisRequest, request: Request):
    user = await get_current_user(request)
    
    lang_code = req.target_language
    if lang_code == "de":
        doc = await db.documents.find_one({"id": doc_id, "user_id": user["_id"]}, {"_id": 0})
        if not doc or not doc.get("analysis"):
            raise HTTPException(status_code=404, detail="Dokument nicht gefunden")
        return {"analysis": doc["analysis"], "language": "de"}
    
    # Check cache
    doc = await db.documents.find_one({"id": doc_id, "user_id": user["_id"]}, {"_id": 0})
    if not doc or not doc.get("analysis"):
        raise HTTPException(status_code=404, detail="Dokument nicht gefunden")
    
    cached = doc.get("translated_analyses", {}).get(lang_code)
    if cached:
        return {"analysis": cached, "language": lang_code}
    
    lang_name = LANG_MAP.get(lang_code, "English")
    analysis = doc["analysis"]
    
    import json as json_mod
    try:
        chat = LlmChat(
            api_key=EMERGENT_KEY,
            session_id=f"translate-{doc_id}-{lang_code}",
            system_message=f"""You are a professional translator. Translate the following document analysis JSON from German to {lang_name}. 
Keep the JSON structure exactly the same. Only translate the text values. 
Do NOT translate: dates, amounts, names of organizations/people, currency values.
Translate: summary, explanation_easy, user_options labels and drafts.
Keep priority values as-is (Low/Medium/High/Urgent).
Return ONLY valid JSON, no other text."""
        ).with_model("gemini", "gemini-3-flash-preview")
        
        msg = UserMessage(text=f"Translate this analysis to {lang_name}:\n{json_mod.dumps(analysis, ensure_ascii=False)}")
        response = await chat.send_message(msg)
        
        translated = parse_ai_json(response)
        
        # Cache translation
        await db.documents.update_one(
            {"id": doc_id},
            {"$set": {f"translated_analyses.{lang_code}": translated}}
        )
        
        return {"analysis": translated, "language": lang_code}
    except Exception as e:
        logger.error(f"Translation failed: {e}")
        return {"analysis": analysis, "language": "de"}

# Generate full response text for an option (subscribers only)
class GenerateTextRequest(BaseModel):
    doc_id: str
    option_label: str
    target_language: str = "Deutsch"

@api_router.post("/documents/generate-text")
async def generate_response_text(req: GenerateTextRequest, request: Request):
    user = await get_current_user(request)
    require_subscription(user)
    
    # Get document
    doc = await db.documents.find_one({"id": req.doc_id, "user_id": user["_id"]}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Dokument nicht gefunden")
    
    if not doc.get("analysis"):
        raise HTTPException(status_code=400, detail="Dokument wurde noch nicht analysiert")
    
    analysis = doc["analysis"]
    
    try:
        # Initialize Gemini chat for text generation
        chat = LlmChat(
            api_key=EMERGENT_KEY,
            session_id=f"text-gen-{req.doc_id}-{uuid.uuid4()}",
            system_message=f"""Du bist ein professioneller Schreibassistent. Deine Aufgabe ist es, formelle Briefe und Antworten zu verfassen.

WICHTIG: Schreibe den KOMPLETTEN Text auf {req.target_language}.

STRUKTUR - Der Text MUSS klar strukturiert sein:

1. ABSENDER (Platzhalter)
   [Ihr Name]
   [Ihre Straße und Hausnummer]
   [PLZ Ort]
   [E-Mail]
   [Telefon]

2. EMPFÄNGER
   [Name der Behörde/Firma aus dem Dokument]
   [Adresse falls bekannt]

3. DATUM
   [Ort], [Datum]

4. BETREFF
   Betreff: [Klarer Betreff mit Aktenzeichen falls vorhanden]

5. ANREDE
   Sehr geehrte Damen und Herren,

6. HAUPTTEXT
   - Einleitung (Bezug auf das Schreiben)
   - Hauptanliegen (klar und deutlich)
   - Begründung (falls nötig)
   - Abschluss

7. GRUSSFORMEL
   Mit freundlichen Grüßen
   
   [Ihr Name]
   [Unterschrift]

Der Text muss:
- Professionell und höflich formuliert sein
- Rechtssicher und klar verständlich sein
- Sofort verwendbar sein
"""
        ).with_model("gemini", "gemini-3-flash-preview")
        
        # Find the selected option
        selected_option = None
        for opt in analysis.get("user_options", []):
            if opt.get("label") == req.option_label:
                selected_option = opt
                break
        
        if not selected_option:
            raise HTTPException(status_code=400, detail="Option nicht gefunden")
        
        prompt = f"""Basierend auf diesem Dokument:
- Absender: {analysis.get('sender', 'Unbekannt')}
- Zusammenfassung: {analysis.get('summary', '')}
- Betrag: {analysis.get('amount_due', 'Nicht angegeben')}
- Frist: {analysis.get('deadline', 'Keine Frist')}

Der Nutzer möchte folgende Aktion durchführen: "{req.option_label}"

Entwurf-Idee: {selected_option.get('draft', '')}

Bitte schreibe einen VOLLSTÄNDIGEN, formellen Brief auf {req.target_language} für diese Aktion. 
Der Brief soll sofort verwendbar sein (mit Platzhaltern für persönliche Daten wie [Ihr Name], [Ihre Adresse], [Datum] etc.)."""

        user_message = UserMessage(text=prompt)
        response = await chat.send_message(user_message)
        
        return {
            "generated_text": response,
            "option_label": req.option_label,
            "target_language": req.target_language
        }
        
    except Exception as e:
        logger.error(f"Text generation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Textgenerierung fehlgeschlagen: {str(e)}")


# Improve generated text based on user feedback (subscribers only)
class ImproveTextRequest(BaseModel):
    original_text: str
    improvement_request: str
    target_language: str = "Deutsch"

@api_router.post("/documents/improve-text")
async def improve_text(req: ImproveTextRequest, request: Request):
    user = await get_current_user(request)
    require_subscription(user)
    
    try:
        # Initialize Gemini chat for text improvement
        chat = LlmChat(
            api_key=EMERGENT_KEY,
            session_id=f"text-improve-{uuid.uuid4()}",
            system_message=f"""Du bist ein professioneller Schreibassistent. Der Nutzer hat einen Text und möchte ihn verbessern.

WICHTIG: 
- Schreibe den verbesserten Text auf {req.target_language}
- Behalte die grundlegende Struktur bei, es sei denn, der Nutzer bittet um eine Änderung
- Setze die Verbesserungswünsche des Nutzers präzise um
- Der Text soll professionell und sofort verwendbar bleiben
"""
        ).with_model("gemini", "gemini-3-flash-preview")
        
        prompt = f"""Hier ist der ursprüngliche Text:

---
{req.original_text}
---

Der Nutzer möchte folgende Verbesserung:
"{req.improvement_request}"

Bitte verbessere den Text entsprechend der Anfrage auf {req.target_language}. 
Gib NUR den verbesserten Text aus, keine Erklärungen."""

        user_message = UserMessage(text=prompt)
        response = await chat.send_message(user_message)
        
        return {
            "improved_text": response,
            "target_language": req.target_language
        }
        
    except Exception as e:
        logger.error(f"Text improvement failed: {e}")
        raise HTTPException(status_code=500, detail=f"Textverbesserung fehlgeschlagen: {str(e)}")


@api_router.get("/files/{path:path}")
async def download_file(path: str, request: Request):
    user = await get_current_user(request)
    
    # Verify user owns this file
    doc = await db.documents.find_one({"storage_path": path, "user_id": user["_id"]})
    if not doc:
        raise HTTPException(status_code=404, detail="Datei nicht gefunden")
    
    try:
        data, content_type = get_object(path)
        return Response(content=data, media_type=content_type)
    except Exception as e:
        logger.error(f"File download failed: {e}")
        raise HTTPException(status_code=500, detail="Datei-Download fehlgeschlagen")

# Stripe Payment Endpoints
import stripe as stripe_lib

@api_router.post("/payments/checkout")
async def create_checkout(checkout_req: CheckoutRequest, request: Request):
    user = await get_current_user(request)
    
    stripe_lib.api_key = os.environ.get("STRIPE_API_KEY")
    stripe_price_id = os.environ.get("STRIPE_PRICE_ID")
    
    success_url = f"{checkout_req.origin_url}/payment/success?session_id={{CHECKOUT_SESSION_ID}}"
    cancel_url = f"{checkout_req.origin_url}/payment/cancel"
    
    try:
        session = stripe_lib.checkout.Session.create(
            mode="subscription",
            line_items=[{"price": stripe_price_id, "quantity": 1}],
            success_url=success_url,
            cancel_url=cancel_url,
            customer_email=user["email"],
            metadata={
                "user_id": user["_id"],
                "user_email": user["email"],
                "product": "monthly_subscription"
            }
        )
        
        # Store payment transaction
        await db.payment_transactions.insert_one({
            "session_id": session.id,
            "user_id": user["_id"],
            "amount": SUBSCRIPTION_PRICE,
            "currency": "eur",
            "status": "pending",
            "payment_status": "initiated",
            "created_at": datetime.now(timezone.utc).isoformat()
        })
        
        return {"url": session.url, "session_id": session.id}
    except Exception as e:
        logger.error(f"Checkout failed: {e}")
        raise HTTPException(status_code=500, detail=f"Checkout fehlgeschlagen: {str(e)}")

@api_router.get("/payments/status/{session_id}")
async def get_payment_status(session_id: str, request: Request):
    user = await get_current_user(request)
    
    stripe_lib.api_key = os.environ.get("STRIPE_API_KEY")
    
    try:
        session = stripe_lib.checkout.Session.retrieve(session_id)
        
        # Update transaction and user subscription if paid
        transaction = await db.payment_transactions.find_one({"session_id": session_id})
        if transaction and transaction.get("payment_status") != "paid" and session.payment_status == "paid":
            await db.payment_transactions.update_one(
                {"session_id": session_id},
                {"$set": {"status": session.status, "payment_status": session.payment_status}}
            )
            # Activate subscription
            await db.users.update_one(
                {"_id": user["_id"]},
                {"$set": {
                    "subscription_status": "active",
                    "subscription_started_at": datetime.now(timezone.utc).isoformat(),
                    "stripe_subscription_id": session.subscription
                }}
            )
        
        return {
            "status": session.status,
            "payment_status": session.payment_status,
            "amount_total": session.amount_total,
            "currency": session.currency
        }
    except Exception as e:
        logger.error(f"Payment status check failed: {e}")
        raise HTTPException(status_code=500, detail="Zahlungsstatus konnte nicht abgerufen werden")

@api_router.post("/webhook/stripe")
async def stripe_webhook(request: Request):
    body = await request.body()
    
    stripe_lib.api_key = os.environ.get("STRIPE_API_KEY")
    
    try:
        event = stripe_lib.Event.construct_from(
            stripe_lib.util.json.loads(body), stripe_lib.api_key
        )
        
        if event.type == "checkout.session.completed":
            session = event.data.object
            if session.payment_status == "paid":
                user_id = session.metadata.get("user_id")
                if user_id:
                    await db.users.update_one(
                        {"_id": user_id},
                        {"$set": {"subscription_status": "active"}}
                    )
        elif event.type == "customer.subscription.deleted":
            sub = event.data.object
            # Find user by subscription and deactivate
            await db.users.update_one(
                {"stripe_subscription_id": sub.id},
                {"$set": {"subscription_status": "inactive"}}
            )
        
        return {"received": True}
    except Exception as e:
        logger.error(f"Webhook handling failed: {e}")
        return {"received": True}

# Health check
@api_router.get("/")
async def root():
    return {"message": "Bureaucracy Intelligence Engine API"}

# Include the router in the main app
app.include_router(api_router)

# CORS
frontend_url = os.environ.get('FRONTEND_URL', 'http://localhost:3000')
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=[
        frontend_url,
        "http://localhost:3000",
        "https://bureau-smart.preview.emergentagent.com"
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Startup events
@app.on_event("startup")
async def startup():
    # Create indexes
    await db.users.create_index("email", unique=True)
    await db.password_reset_tokens.create_index("expires_at", expireAfterSeconds=0)
    await db.login_attempts.create_index("identifier")
    await db.documents.create_index("user_id")
    await db.documents.create_index("id", unique=True)
    
    # Seed admin
    admin_email = os.environ.get("ADMIN_EMAIL", "admin@example.com")
    admin_password = os.environ.get("ADMIN_PASSWORD", "admin123")
    
    existing = await db.users.find_one({"email": admin_email})
    if existing is None:
        hashed = hash_password(admin_password)
        await db.users.insert_one({
            "email": admin_email,
            "password_hash": hashed,
            "name": "Admin",
            "role": "admin",
            "subscription_status": "active",
            "created_at": datetime.now(timezone.utc).isoformat()
        })
        logger.info(f"Admin user created: {admin_email}")
    elif not verify_password(admin_password, existing["password_hash"]):
        await db.users.update_one({"email": admin_email}, {"$set": {"password_hash": hash_password(admin_password)}})
        logger.info("Admin password updated")
    
    # Write test credentials
    try:
        os.makedirs("/app/memory", exist_ok=True)
        with open("/app/memory/test_credentials.md", "w") as f:
            f.write("# Test Credentials\n\n")
            f.write(f"## Admin\n- Email: {admin_email}\n- Password: {admin_password}\n- Role: admin\n\n")
            f.write("## Auth Endpoints\n- POST /api/auth/register\n- POST /api/auth/login\n- POST /api/auth/logout\n- GET /api/auth/me\n")
    except Exception as e:
        logger.warning(f"Could not write test credentials: {e}")
    
    # Init storage
    try:
        init_storage()
    except Exception as e:
        logger.warning(f"Storage init deferred: {e}")

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
