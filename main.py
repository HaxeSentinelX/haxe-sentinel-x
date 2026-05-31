from fastapi import FastAPI
from pydantic import BaseModel
from database import engine
from models import Base
from fastapi import Depends
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from fastapi import UploadFile, File
from database import get_db
from models import Base, UserDB, IncidentDB

app = FastAPI()
Base.metadata.create_all(bind=engine)
users = []

@app.get("/")
def home():
    return {"message": "HAXE Sentinel X is running"}

@app.get("/status")
def status():
    return {
        "project": "HAXE Sentinel X",
        "version": "1.0",
        "status": "Online"
    }

class User(BaseModel):
    username: str
    email: str
    password: str
class LoginRequest(BaseModel):
    email: str
    password: str

@app.post("/register")
def register(user: User, db: Session = Depends(get_db)):

    try:
        new_user = UserDB(
    username=user.username,
    email=user.email,
    password=user.password
)

        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        return {
            "message": "User saved successfully",
            "id": new_user.id
        }

    except IntegrityError:
        db.rollback()

        return {
            "error": "Email already exists"
        }
@app.get("/users")
def get_users(db: Session = Depends(get_db)):
    return db.query(UserDB).all()
@app.post("/login")
def login(user: LoginRequest, db: Session = Depends(get_db)):

    existing_user = db.query(UserDB).filter(
        UserDB.email == user.email
    ).first()

    if not existing_user:
        return {
            "success": False,
            "message": "User not found"
        }

    if existing_user.password != user.password:
        return {
            "success": False,
            "message": "Wrong password"
        }

    return {
        "success": True,
        "message": "Login successful",
        "username": existing_user.username
    }
@app.post("/upload-log")
async def upload_log(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):

    content = await file.read()
    text = content.decode("utf-8")

    threats = []
    risk_score = 0

    if "Failed Login" in text:
        threats.append("Possible Brute Force Attack")
        risk_score += 30

    if "PowerShell" in text:
        threats.append("Suspicious PowerShell Activity")
        risk_score += 40

    if "EncodedCommand" in text:
        threats.append("Encoded PowerShell Command")
        risk_score += 30

    if "Mimikatz" in text:
        threats.append("Credential Dumping Detected")
        risk_score += 50

    severity = "LOW"

    if risk_score >= 80:
        severity = "CRITICAL"
    elif risk_score >= 60:
        severity = "HIGH"
    elif risk_score >= 30:
        severity = "MEDIUM"

    incident = IncidentDB(
        filename=file.filename,
        risk_score=risk_score,
        severity=severity,
        threats=", ".join(threats)
    )

    db.add(incident)
    db.commit()

    return {
        "filename": file.filename,
        "risk_score": risk_score,
        "severity": severity,
        "threats": threats
    }
@app.get("/incidents")
def get_incidents(db: Session = Depends(get_db)):
    return db.query(IncidentDB).all()
@app.get("/dashboard")
def dashboard(db: Session = Depends(get_db)):

    incidents = db.query(IncidentDB).all()

    total_incidents = len(incidents)

    critical_incidents = len(
        [i for i in incidents if i.severity == "CRITICAL"]
    )

    high_incidents = len(
        [i for i in incidents if i.severity == "HIGH"]
    )

    medium_incidents = len(
        [i for i in incidents if i.severity == "MEDIUM"]
    )

    low_incidents = len(
        [i for i in incidents if i.severity == "LOW"]
    )

    return {
    "platform": "HAXE Sentinel X",
    "version": "0.3",
    "total_incidents": total_incidents,
    "critical_incidents": critical_incidents,
    "high_incidents": high_incidents,
    "medium_incidents": medium_incidents,
    "low_incidents": low_incidents
}