# main.py - FINAL ROBUST VERSION FOR PRODUCTION
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone

# --- Configuration ---
DATABASE_URL = "postgresql://kakamega_db_user:GuMJ3n0l9KqlGdCmATffQfwhrDzKlW3W@dpg-d2s19iripnbc73e4b840-a/kakamega_db"
SECRET_KEY = "a_very_secret_key_for_jwt"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# --- Database Setup ---
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- Security ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

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

# --- Database Models (SQLAlchemy) ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    staff_number = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=False)
    hashed_pin = Column(String, nullable=False)

# --- Pydantic Models (Schemas) ---
class Token(BaseModel):
    access_token: str
    token_type: str
    user_data: dict

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

# --- THE FIX: We create the tables here, outside of any event ---
# This code runs only ONCE when the file is first loaded by Python.
# It is the simplest and most reliable way to ensure tables exist.
Base.metadata.create_all(bind=engine)

# --- API Endpoints ---
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # Check if any users exist. If not, create them.
    # This is a safe way to add initial data.
    if db.query(User).count() == 0:
        users_to_create = [
            {"staff_number": "85891", "pin": "8589", "full_name": "Martin Karanja"},
            {"staff_number": "16957", "pin": "1695", "full_name": "Godfrey"},
            {"staff_number": "12345", "pin": "1234", "full_name": "Jane Doe"},
        ]
        for user_data in users_to_create:
            hashed_pin = get_pin_hash(user_data["pin"])
            db_user = User(
                staff_number=user_data["staff_number"],
                hashed_pin=hashed_pin,
                full_name=user_data["full_name"]
            )
            db.add(db_user)
        db.commit()

    # Now, proceed with login
    user = db.query(User).filter(User.staff_number == form_data.username).first()
    if not user or not verify_pin(form_data.password, user.hashed_pin):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect staff number or PIN",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.staff_number}, expires_delta=access_token_expires
    )
    user_data = {"staff_number": user.staff_number, "full_name": user.full_name}
    return {"access_token": access_token, "token_type": "bearer", "user_data": user_data}

@app.get("/")
def read_root():
    return {"Status": "Kakamega Field Ops API is running"}
