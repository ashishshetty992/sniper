from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.crud.agent import create_agent as crud_create_agent
from app.crud.agent import get_agent as crud_get_agent
from app.crud.agent import get_agents as crud_get_agents
from app.crud.agent import get_agents_with_profiles as crud_get_agents_with_profiles
from app.schemas.agent import AgentCreate
from app.models.response import AgentResponseModel
from app import dependencies
from typing import List
import pdb

router = APIRouter()

@router.post("/agents/", response_model=AgentResponseModel)
def create_agent(agent: AgentCreate, db: Session = Depends(dependencies.get_db)):
    return crud_create_agent(db, agent)

@router.get("/agents/{agent_id}", response_model=AgentResponseModel)
def read_agent(agent_id: int, db: Session = Depends(dependencies.get_db)):
    agent = crud_get_agent(db, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent

@router.get("/agents/", response_model=List[AgentResponseModel])
def read_agents(skip: int = 0, limit: int = 10, db: Session = Depends(dependencies.get_db)):
    agents = crud_get_agents(db, skip, limit)
    return agents

@router.get("/allagentprofiles/")
def read_agent_profiles(skip: int = 0, limit: int = 10, db: Session = Depends(dependencies.get_db)):
    agent_profiles = crud_get_agents_with_profiles(db, skip, limit)
    return agent_profiles