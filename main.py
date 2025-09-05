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

# --- Database Configuration ---
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("No DATABASE_URL environment variable set")

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
SECRET_KEY = "a_very_secret_key_for_jwt" # In production, use environment variables
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
class Token(BaseModel):
    access_token: str
    token_type: str
    user_data: dict

class TokenData(BaseModel):
    staff_number: str | None = None

# --- FastAPI App Instance ---
app = FastAPI()

# --- CORS Middleware ---
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

def create_access_token(data: dict, expires_delta: timedelta | None = None):
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

# --- Create Database Tables on Startup ---
# This is a robust way to ensure tables exist before the app starts serving requests.
try:
    print("Creating database tables...")
    Base.metadata.create_all(bind=engine)
    print("Database tables created or already exist.")
except Exception as e:
    print(f"Error creating database tables: {e}")
    # We don't raise an error here to allow the app to start,
    # the user creation logic will handle the rest.

# --- API Endpoints ---
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # THIS IS THE NEW ROBUST LOGIC
    # Check and create users if the table is empty, every time someone tries to log in.
    create_initial_users(db)

    user = db.query(User).filter(User.staff_number == form_data.username).first()
    if not user or not verify_pin(form_data.password, user.hashed_pin):
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
