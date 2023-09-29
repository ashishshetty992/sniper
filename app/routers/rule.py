from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app import crud, models, security, schemas
from app.schemas import Rule
from app.database import get_db

router = APIRouter()

# Route for creating a new rule
@router.post("/", response_model = Rule)
def create_rule(rule: schemas.RuleCreate, db: Session = Depends(get_db), current_user: models.Admin = Depends(security.get_current_user)):
    return crud.create_rule(db, rule)

# Route for getting a rule by ID
@router.get("/{rule_id}", response_model = Rule)
def read_rule(rule_id: int, db: Session = Depends(get_db), current_user: models.Admin = Depends(security.get_current_user)):
    return crud.get_rule(db, rule_id)
