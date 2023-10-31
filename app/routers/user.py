from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.crud.user import Crud
from app.crud.role import get_roles_by_ids
from app.schemas.user import UserCreate
from app.schemas.response import UserResponseSchema
from typing import List
from app.dependencies import get_db
from app.models.user import User
from app.models.role import Role
from app.oauth_user import get_current_user
import pdb

router = APIRouter()

SUPERADMIN = "superadmin"
ADMIN = "admin"

def get_current_user_details(db: Session, user: User):
    current_user_details = Crud.get_user(db, user)
    return current_user_details

def get_roles(db: Session, role_ids: Role):
    roles = get_roles_by_ids(db, role_ids)
    return roles

@router.post("/users/", response_model=UserResponseSchema, response_model_exclude_none=True)
def create_user(user: UserCreate, role_ids: List[int], db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    current_user_details = get_current_user_details(db, current_user.username)
    current_user_roles = current_user_details.roles
    roles = get_roles(db, role_ids)
    # role_names = [role.name for role in roles]

    # Check if the current user is not a superadmin and is an admin
    if not current_user_details.is_superadmin and ADMIN in [role.name for role in current_user_roles]:
        # Admins can only create users
        if user.is_superadmin == True:
            raise HTTPException(status_code=403, detail="Admins cannot create superadmins")
        return Crud.create_user(db, user, role_ids)

    # Check if the current user is a superadmin
    if current_user_details.is_superadmin:
        # Superadmins can create both admins and users
        return Crud.create_user(db, user, role_ids)

    # If none of the conditions matched, return an error
    raise HTTPException(status_code=403, detail="You do not have permission to create users")

# @router.post("/users/")
# def create_user(user: UserCreate, role_ids: List[int], db: Session = Depends(get_db)):
#     roles = get_roles(db, role_ids)
#     return Crud.create_user(db, user, role_ids)