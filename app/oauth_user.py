
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timedelta
from typing import Optional
from app.crud.user import Crud  # Import the Crud class from app.crud.user
from app.schemas.oauth import Token
from app.models.user import User  # Import your User model here
from app.core import get_password_hash, verify_password
from sqlalchemy.orm import Session
# from typing import Annotated, Union
# from pydantic import BaseModel
# from app.models.token import TokenData
from jose import JWTError, jwt
from app.models.token import TokenData
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi import Depends, HTTPException, status

import pdb

SECRET_KEY = "ASHISH"  # Replace with your own secret key
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1000

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    return token_data

def get_current_active_user_authenticated(current_user: TokenData = Depends(get_current_user)):
    if current_user.username is None:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

def get_user_details(username: str):
    user = Crud.get_user(db, username)