from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime, timedelta
from passlib.context import CryptContext
import pyodbc
import secrets

def get_db():
    return pyodbc.connect(
        'DRIVER={ODBC Driver 17 for SQL Server};'
        'SERVER=agritechco.database.windows.net;'
        'DATABASE=3Dto3DReconstruction;'
        'UID=agritech;'
        'PWD=Poiuyt$1234;'
    )

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class RegisterInput(BaseModel):
    username: str
    email: str
    password: str

class LoginInput(BaseModel):
    email: str
    password: str

class TokenInput(BaseModel):
    userId: int

class ModelUpload(BaseModel):
    fileName: str
    fileData: str  # Base64 string in real use (simplified here)

class RequestCreate(BaseModel):
    modelName: str
    imageId: int
    tokenId: int

class PaymentInput(BaseModel):
    userId: int
    typeId: int

class UsageLog(BaseModel):
    tokenId: int
    value: str

app = FastAPI()

# === USERS ===
@app.post("/register")
def register(data: RegisterInput):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT Id FROM Users WHERE Email = ?", data.email)
    if cursor.fetchone():
        raise HTTPException(400, "Email already registered")
    hashed = pwd_context.hash(data.password)
    cursor.execute("INSERT INTO Users (Username, Email, UserPassword) VALUES (?, ?, ?)",
                   data.username, data.email, hashed)
    db.commit()
    return {"message": "User created"}

@app.post("/login")
def login(data: LoginInput):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT Id, UserPassword FROM Users WHERE Email = ?", data.email)
    user = cursor.fetchone()
    if not user or not pwd_context.verify(data.password, user.UserPassword):
        raise HTTPException(401, "Invalid credentials")
    return {"message": "Login successful", "userId": user.Id}

@app.post("/token/generate")
def generate_token(data: TokenInput):
    db = get_db()
    cursor = db.cursor()
    token = secrets.token_urlsafe(32)
    expiration = datetime.utcnow() + timedelta(days=7)
    cursor.execute("INSERT INTO Token (TokenString, ExpirationDate, UserID) VALUES (?, ?, ?)",
                   token, expiration, data.userId)
    db.commit()
    return {"token": token, "expires": expiration}

@app.get("/token/validate/{token}")
def validate_token(token: str):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT Id, ExpirationDate FROM Token WHERE TokenString = ?", token)
    row = cursor.fetchone()
    if not row:
        raise HTTPException(404, "Token not found")
    if datetime.utcnow() > row.ExpirationDate:
        raise HTTPException(403, "Token expired")
    return {"status": "valid", "tokenId": row.Id}

@app.post("/model/upload")
def upload_model(data: ModelUpload):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("INSERT INTO ThreeDModels (FileName, FileData) VALUES (?, ?)",
                   data.fileName, data.fileData.encode())  # Assuming binary string
    db.commit()
    return {"message": "Model uploaded"}

@app.post("/request/create")
def create_request(data: RequestCreate):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("INSERT INTO Requests (ModelName, StatusId, ImageId, TokenID) VALUES (?, ?, ?, ?)",
                   data.modelName, 1, data.imageId, data.tokenId)
    db.commit()
    return {"message": "Request created"}

@app.get("/request/list/{tokenId}")
def list_requests(tokenId: int):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT r.Id, r.ModelName, s.Name AS Status, t.FileName
        FROM Requests r
        JOIN Status s ON r.StatusId = s.Id
        JOIN ThreeDModels t ON r.ImageId = t.Id
        WHERE r.TokenID = ?
    """, tokenId)
    rows = cursor.fetchall()
    return [{"id": r.Id, "model": r.ModelName, "status": r.Status, "filename": r.FileName} for r in rows]

@app.post("/payment/create")
def create_payment(data: PaymentInput):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("INSERT INTO Payment (UserId, TypeId, IsPaid) VALUES (?, ?, ?)",
                   data.userId, data.typeId, 1)
    db.commit()
    return {"message": "Payment successful"}

@app.get("/payment/status/{userId}")
def payment_status(userId: int):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT TOP 1 IsPaid, PaymentDate FROM Payment WHERE UserId = ? ORDER BY PaymentDate DESC", userId)
    row = cursor.fetchone()
    if not row:
        return {"paid": False}
    return {"paid": row.IsPaid, "date": row.PaymentDate}

@app.get("/payment/methods")
def payment_methods():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT Id, Name FROM PaymentType")
    return [{"id": row.Id, "name": row.Name} for row in cursor.fetchall()]

@app.post("/usage/log")
def log_usage(data: UsageLog):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("INSERT INTO Usage (TokenId, Value) VALUES (?, ?)", data.tokenId, data.value)
    db.commit()
    return {"message": "Logged"}

@app.get("/usage/stats/{tokenId}")
def usage_stats(tokenId: int):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT COUNT(*) FROM Usage WHERE TokenId = ?", tokenId)
    count = cursor.fetchone()[0]
    return {"requests": count}
@app.get("/test")
def test_api():
    return {"It worked"}
