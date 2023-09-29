from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app import crud, models, security, schemas
from app.schemas import Profile
from app.database import get_db

router = APIRouter()

# Route for creating a new profile
@router.post("/", response_model=Profile)
def create_profile(profile: schemas.ProfileCreate, db: Session = Depends(get_db), current_user: models.Admin = Depends(security.get_current_user)):
    return crud.create_profile(db, profile)

# Route for getting a profile by ID
@router.get("/{profile_id}", response_model=Profile)
def read_profile(profile_id: int, db: Session = Depends(get_db), current_user: models.Admin = Depends(security.get_current_user)):
    return crud.get_profile(db, profile_id)
