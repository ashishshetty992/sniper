from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import SessionLocal, engine
from app.schemas import role as role_schemas
from app.schemas.response import RoleResponseSchema
from app.crud import role as role_crud
from app.models import role as role_models
import pdb
from app.dependencies import get_db  # Import the get_db function
from typing import List


router = APIRouter()


# Function to get a role by role_id
def get_role(role_id: int, db: Session = Depends(get_db)):
    role = role_crud.get_role(db, role_id)
    if role is None:
        raise HTTPException(status_code=404, detail="Role not found")
    return role

# Create a new role
@router.post("/roles/")
def create_role(role: role_schemas.RoleCreate, db: Session = Depends(get_db)):
    return role_crud.create_role(db, role)

# Get role by role_id
@router.get("/roles/{role_id}")
def read_role(role_id: int, db: Session = Depends(get_db)):
    role = get_role(role_id, db)
    return role

@router.get("/roles/")
def get_roles(db: Session = Depends(get_db), skip: int = 0, limit: int = 10, ):
    roles = role_crud.get_roles(db)
    return roles



# # Update role by role_id
# @router.put("/roles/{role_id}", response_model=role_schemas.Role)
# def update_role(role_id: int, role: role_schemas.RoleUpdate, db: Session = Depends(get_db)):
#     updated_role = role_crud.update_role(db, role_id, role)
#     if updated_role is None:
#         raise HTTPException(status_code=404, detail="Role not found")
#     return updated_role

# # Delete role by role_id
# @router.delete("/roles/{role_id}", response_model=role_schemas.Role)
# def delete_role(role_id: int, db: Session = Depends(get_db)):
#     deleted_role = role_crud.delete_role(db, role_id)
#     if deleted_role is None:
#         raise HTTPException(status_code=404, detail="Role not found")
#     return deleted_role
