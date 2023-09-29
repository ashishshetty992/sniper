from datetime import datetime, timedelta
from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from app import models, schemas
from app.database import SessionLocal
from app.config import settings

# Define a security context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Create an instance of OAuth2PasswordBearer for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Function to create a new access token
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

# Function to verify the password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Function to get a user by username
def get_user(db, username: str):
    return db.query(models.User).filter(models.User.username == username).first()

# Function to authenticate a user
def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return None
    if not verify_password(password, user.password):
        return None
    return user

# Dependency to get the current user
def get_current_user(token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(SessionLocal)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = schemas.TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

# Dependency to check if a user has admin privileges
def is_admin(user: models.User = Depends(get_current_user)):
    if user.is_admin:
        return True
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User does not have admin privileges")
