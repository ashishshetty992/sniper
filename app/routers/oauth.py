from fastapi import APIRouter, Depends

from app.schemas.oauth import Token
from app.oauth_user import get_current_user
from app.models.user import User
from app.schemas.response import UserResponseSchema,TokenResponseSchema
from app.crud.user import Crud
# from app.crud.admin import Crud
from fastapi.security import OAuth2PasswordRequestForm
from app.dependencies import get_db
from sqlalchemy.orm import Session
from app.oauth_user import create_access_token
# from app.oauth_admin import create_access_token
import pdb
from datetime import datetime, timedelta

router = APIRouter()
ACCESS_TOKEN_EXPIRE_MINUTES = 1000

@router.post("/token", response_model=TokenResponseSchema)
def login_for_access_token(db: Session = Depends(get_db), form_data: OAuth2PasswordRequestForm = Depends()):
    print(form_data)
    username = form_data.username
    password = form_data.password
    user = Crud.authenticate_user(db, username, password)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/users/current", response_model=UserResponseSchema)
def read_users_me(db: Session = Depends(get_db), current_user: Token = Depends(get_current_user)):
    username = current_user.username
    user = Crud.get_user(db, username)
    return user