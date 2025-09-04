# main.py - FINAL CORRECTED VERSION FOR PRODUCTION

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from fastapi.middleware.cors import CORSMiddleware

# --- Absolute Imports (The Fix for ImportError) ---
import models
import database
from database import engine

# --- Database Setup ---
# This line ensures the tables are created if they don't exist
models.Base.metadata.create_all(bind=engine)

# --- App Initialization ---
app = FastAPI(title="Kakamega Field Ops API")

# --- CORS MIDDLEWARE SETUP ---
# This allows your Netlify frontend to connect to this backend
origins = [
    "https://kakamega-field-ops.netlify.app",
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Security and Hashing Configuration ---
SECRET_KEY = "a_very_secret_key_for_jwt"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- Helper Functions ---

# Dependency to get a DB session
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# --- API Endpoints ---

@app.get("/")
def read_root():
    """A simple endpoint to check if the API is running."""
    return {"message": "Kakamega Field Ops API is running and accessible"}

@app.post("/token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    Handles the login request.
    Takes username (staff number) and password (PIN) from a form.
    Returns a JWT access token if credentials are correct.
    """
    # Using the hardcoded credentials as requested
    is_correct_username = form_data.username == "85891"
    is_correct_password = form_data.password == "8589"

    if not (is_correct_username and is_correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect staff number or PIN",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": form_data.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}
