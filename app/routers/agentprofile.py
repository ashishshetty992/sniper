from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.crud.agentprofile import create_agent_profile as crud_create_agent_profile
from app.crud.agentprofile import get_agent_profile as crud_get_agent_profile
from app.crud.agentprofile import get_agent_profiles as crud_get_agent_profiles
from app.crud.agentprofile import get_profiles_with_agents as crud_get_profiles_with_agents
from app.schemas.agentprofile import AgentProfileCreate
from app.models.response import AgentProfileResponseModel
from app import dependencies
from typing import List

router = APIRouter()

@router.post("/agentprofiles/", response_model=AgentProfileResponseModel)
def create_agent_profile(agent_profile: AgentProfileCreate, agent_ids: List[int], db: Session = Depends(dependencies.get_db)):
    return crud_create_agent_profile(db, agent_profile, agent_ids)

@router.get("/agentprofiles/{agent_profile_id}", response_model=AgentProfileResponseModel)
def read_agent_profile(agent_profile_id: int, db: Session = Depends(dependencies.get_db)):
    agent_profile = crud_get_agent_profile(db, agent_profile_id)
    if agent_profile is None:
        raise HTTPException(status_code=404, detail="Agent Profile not found")
    return agent_profile

@router.get("/agentprofiles/", response_model=List[AgentProfileResponseModel])
def read_agent_profiles(skip: int = 0, limit: int = 10, db: Session = Depends(dependencies.get_db)):
    agent_profiles = crud_get_agent_profiles(db, skip, limit)
    return agent_profiles

@router.get("/allprofilesagent/")
def read_agent_profiles(skip: int = 0, limit: int = 10, db: Session = Depends(dependencies.get_db)):
    agent_profiles = crud_get_profiles_with_agents(db, skip, limit)
    return agent_profiles