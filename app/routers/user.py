from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app import crud, models, security,schemas
from app.schemas import User
from app.database import get_db

router = APIRouter()

# Route for creating a new user
@router.post("/", response_model=User)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db), current_user: models.Admin = Depends(security.get_current_user)):
    return crud.create_user(db, user)

# Route for getting a user by ID
@router.get("/{user_id}", response_model=User)
def read_user(user_id: int, db: Session = Depends(get_db), current_user: models.Admin = Depends(security.get_current_user)):
    return crud.get_user(db, user_id)
