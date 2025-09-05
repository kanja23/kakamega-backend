# FINAL main.py
import os
import time
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from typing import Optional

# --- Database Configuration ---
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    # Fallback for local development
    DATABASE_URL = "postgresql://username:password@localhost/dbname"
    print(f"Using fallback DATABASE_URL: {DATABASE_URL}")

# Connect to the database with retry logic
engine = None
for i in range(5):
    try:
        engine = create_engine(DATABASE_URL)
        with engine.connect() as connection:
            print("Database connection successful.")
        break
    except Exception as e:
        print(f"Database connection failed (attempt {i+1}/5): {e}")
        if i < 4:
            time.sleep(5)
        else:
            raise

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- Security Configuration ---
SECRET_KEY = os.getenv("SECRET_KEY", "a_very_secret_key_for_jwt")  # Use environment variable in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- Database Models ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    staff_number = Column(String, unique=True, index=True)
    full_name = Column(String)
    hashed_pin = Column(String)

# --- Pydantic Models (Data Schemas) ---
class UserBase(BaseModel):
    staff_number: str
    full_name: str

class UserCreate(UserBase):
    pin: str

class UserInDB(UserBase):
    id: int
    hashed_pin: str

    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str
    user_data: dict

class TokenData(BaseModel):
    staff_number: Optional[str] = None

# --- FastAPI App Instance ---
app = FastAPI()

# --- CORS Middleware ---
origins = [
    "https://kakamega-field-ops.netlify.app",
    "http://localhost:3000",
    "http://localhost:8000",  # Added for local testing
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Dependency to get DB session ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Utility Functions ---
def verify_pin(plain_pin, hashed_pin):
    return pwd_context.verify(plain_pin, hashed_pin)

def get_pin_hash(pin):
    return pwd_context.hash(pin)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_initial_users(db: Session):
    # This function creates users ONLY if the table is empty.
    if db.query(User).count() == 0:
        print("Users table is empty. Creating initial users...")
        initial_users = [
            {"staff_number": "85891", "full_name": "Martin Karanja", "pin": "8589"},
            {"staff_number": "16957", "full_name": "Godfrey", "pin": "1695"},
            {"staff_number": "12345", "full_name": "Admin User", "pin": "1234"},
        ]
        for user_data in initial_users:
            hashed_pin = get_pin_hash(user_data["pin"])
            db_user = User(
                staff_number=user_data["staff_number"],
                full_name=user_data["full_name"],
                hashed_pin=hashed_pin
            )
            db.add(db_user)
        db.commit()
        print("Initial users created successfully.")
    else:
        print("Users table already has data. Skipping initial user creation.")

def get_user(db: Session, staff_number: str):
    return db.query(User).filter(User.staff_number == staff_number).first()

# --- Create Database Tables on Startup ---
@app.on_event("startup")
def startup_event():
    try:
        print("Creating database tables...")
        Base.metadata.create_all(bind=engine)
        print("Database tables created or already exist.")
        
        # Create initial users after tables are created
        db = SessionLocal()
        try:
            create_initial_users(db)
        finally:
            db.close()
    except Exception as e:
        print(f"Error during startup: {e}")

# --- API Endpoints ---
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = get_user(db, form_data.username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect staff number or PIN",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not verify_pin(form_data.password, user.hashed_pin):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect staff number or PIN",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user_data_for_token = {
        "id": user.id,
        "staff_number": user.staff_number,
        "full_name": user.full_name
    }
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.staff_number}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer", "user_data": user_data_for_token}

@app.get("/")
def read_root():
    return {"message": "Kakamega Field Ops API is running."}

@app.get("/users/")
def read_users(db: Session = Depends(get_db)):
    users = db.query(User).all()
    return users

# Add a health check endpoint
@app.get("/health")
def health_check():
    return {"status": "healthy", "timestamp": datetime.now()}
