from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app import crud, models, security, schemas
from app.schemas import Admin
from app.database import get_db

router = APIRouter()

# Route for creating a new admin
@router.post("/", response_model=Admin)
def create_admin(admin: schemas.AdminCreate, db: Session = Depends(get_db), current_user: models.User = Depends(security.get_current_user)):
    # Check if the current user has super admin privileges
    if not security.is_super_admin(current_user):
        raise HTTPException(status_code=403, detail="Permission denied. Super admin access required.")
    
    return crud.create_admin(db, admin)

# Route for getting an admin by ID
@router.get("/{admin_id}", response_model=Admin)
def read_admin(admin_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(security.get_current_user)):
    return crud.get_admin(db, admin_id)
