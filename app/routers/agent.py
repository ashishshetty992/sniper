from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app import crud, models, security, schemas
from app.schemas import Agent
from app.database import get_db

router = APIRouter()

# Route for creating a new agent
@router.post("/", response_model=Agent)
def create_agent(agent: schemas.AgentCreate, db: Session = Depends(get_db), current_user: models.Admin = Depends(security.get_current_user)):
    return crud.create_agent(db, agent)

# Route for getting an agent by ID
@router.get("/{agent_id}", response_model=Agent)
def read_agent(agent_id: int, db: Session = Depends(get_db), current_user: models.Admin = Depends(security.get_current_user)):
    return crud.get_agent(db, agent_id)
