from fastapi import HTTPException, Security
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from typing import Optional
from app.config import settings

# Define OAuth2PasswordBearer for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Function to verify and decode the JWT token
def verify_token(token: str = Security(oauth2_scheme, scopes=[])):
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Function to get the current user from the token payload
def get_current_user(token: str = Security(oauth2_scheme, scopes=[])):
    payload = verify_token(token)
    return payload.get("sub")

# Function to check if the user is an admin
def is_admin(token: str = Security(oauth2_scheme, scopes=[])):
    payload = verify_token(token)
    user_roles = payload.get("roles", [])
    if "admin" in user_roles:
        return True
    return False
