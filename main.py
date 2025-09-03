import os
import boto3
from botocore.exceptions import ClientError
from fastapi import FastAPI, Depends, HTTPException, status, Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, Integer, String, Enum, Boolean, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import enum

# --- Configuration ---
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@localhost/kakamega_db")
SECRET_KEY = os.getenv("SECRET_KEY", "a_very_secret_key_for_jwt_tokens")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# AWS S3 Configuration
S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME")
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

s3_client = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=AWS_REGION
)


# --- Database Setup ---
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- Password Hashing ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- User Roles Enum ---
class UserRole(str, enum.Enum):
    field_officer = "field_officer"
    supervisor = "supervisor"
    admin = "admin"

# --- Database Models ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    staff_id = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(UserRole), nullable=False)
    full_name = Column(String, default="Default User")
    first_login = Column(Boolean, default=True)

# --- Pydantic Models (Data Schemas) ---
class UserCreate(BaseModel):
    staff_id: str
    password: str
    role: UserRole
    full_name: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    staff_id: str | None = None

class PasswordChange(BaseModel):
    new_password: str

class PresignedUrlRequest(BaseModel):
    filename: str
    file_type: str

# --- FastAPI App Instance ---
app = FastAPI(title="Kakamega mypower 2.0 API")

# --- Dependency for getting DB session ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Security & Authentication Functions ---
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), db = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        staff_id: str = payload.get("sub")
        if staff_id is None:
            raise credentials_exception
        token_data = TokenData(staff_id=staff_id)
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.staff_id == token_data.staff_id).first()
    if user is None:
        raise credentials_exception
    return user

# --- API Endpoints ---

@app.get("/")
def read_root():
    return {"message": "Welcome to the Kakamega mypower 2.0 API"}

# This endpoint is used to create the initial sample users
@app.post("/create_initial_users", summary="Create initial sample users", include_in_schema=False)
def create_initial_users(db = Depends(get_db)):
    users_to_create = [
        {"staff_id": "85891", "full_name": "Martin (Field Officer)", "role": UserRole.field_officer},
        {"staff_id": "44551", "full_name": "Jane (Supervisor)", "role": UserRole.supervisor},
        {"staff_id": "11221", "full_name": "Admin User", "role": UserRole.admin},
    ]
    
    for user_data in users_to_create:
        user_exists = db.query(User).filter(User.staff_id == user_data["staff_id"]).first()
        if not user_exists:
            initial_password = user_data["staff_id"][:4]
            hashed_password = get_password_hash(initial_password)
            new_user = User(
                staff_id=user_data["staff_id"],
                hashed_password=hashed_password,
                full_name=user_data["full_name"],
                role=user_data["role"],
                first_login=True
            )
            db.add(new_user)
    db.commit()
    return {"message": "Initial users created or already exist."}


@app.post("/token", response_model=Token, summary="Login and get access token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db = Depends(get_db)):
    user = db.query(User).filter(User.staff_id == form_data.username).first()
    
    is_initial_password = False
    if user and user.first_login:
        is_initial_password = (form_data.password == user.staff_id[:4])

    if not user or not (verify_password(form_data.password, user.hashed_password) or is_initial_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect staff ID or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.staff_id}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me", summary="Get current user's details")
async def read_users_me(current_user: User = Depends(get_current_user)):
    return {
        "staff_id": current_user.staff_id,
        "full_name": current_user.full_name,
        "role": current_user.role,
        "first_login": current_user.first_login
    }

@app.post("/users/change-password", summary="Change user password")
async def change_password(password_data: PasswordChange, current_user: User = Depends(get_current_user), db = Depends(get_db)):
    current_user.hashed_password = get_password_hash(password_data.new_password)
    if current_user.first_login:
        current_user.first_login = False
    db.add(current_user)
    db.commit()
    return {"message": "Password updated successfully"}


@app.post("/media/generate-upload-url", summary="Generate a pre-signed URL for S3 upload")
async def create_presigned_url(request_body: PresignedUrlRequest, current_user: User = Depends(get_current_user)):
    if not S3_BUCKET_NAME:
        raise HTTPException(status_code=500, detail="S3 bucket not configured on server.")

    object_name = f"uploads/{current_user.staff_id}/{datetime.utcnow().timestamp()}_{request_body.filename}"

    try:
        response = s3_client.generate_presigned_url('put_object',
                                                    Params={'Bucket': S3_BUCKET_NAME,
                                                            'Key': object_name,
                                                            'ContentType': request_body.file_type},
                                                    ExpiresIn=3600)
    except ClientError as e:
        raise HTTPException(status_code=500, detail=f"Could not generate S3 URL: {e}")

    return {"upload_url": response, "object_key": object_name}

@app.on_event("startup")
def on_startup():
    try:
        Base.metadata.create_all(bind=engine)
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        print("Database connection successful and tables created.")
    except Exception as e:
        print(f"Database connection failed: {e}")
