# main.py - SINGLE-FILE VERSION TO GUARANTEE DEPLOYMENT SUCCESS

import os
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from jose import jwt
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from fastapi.middleware.cors import CORSMiddleware

# ===============================================================
#  DATABASE.PY CODE - NOW INSIDE MAIN.PY
# ===============================================================
# Get the database URL from the environment variables provided by Render
DATABASE_URL = os.getenv("DATABASE_URL")

# A small fix for compatibility between SQLAlchemy and Render's Postgres
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ===============================================================
#  MODELS.PY CODE - NOW INSIDE MAIN.PY
# ===============================================================
# This defines your database tables. We'll keep it simple for now.
# In the future, we can add User, Report, etc. tables here.
class Placeholder(Base):
    __tablename__ = "placeholders"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)

# ===============================================================
#  MAIN APPLICATION LOGIC
# ===============================================================

# This line ensures the tables are created in the database
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Kakamega Field Ops API")

# --- CORS MIDDLEWARE SETUP ---
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

# --- Security Configuration ---
SECRET_KEY = "a_very_secret_key_for_jwt"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- Helper Functions ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# --- API Endpoints ---
@app.get("/")
def read_root():
    return {"message": "Kakamega Field Ops API is running"}

@app.post("/token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    is_correct_username = form_data.username == "85891"
    is_correct_password = form_data.password == "8589"

    if not (is_correct_username and is_correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect staff number or PIN",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_access_token(data={"sub": form_data.username})
    return {"access_token": access_token, "token_type": "bearer"}
