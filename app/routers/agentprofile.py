from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.crud.agentprofile import create_agent_profile as crud_create_agent_profile
from app.crud.agentprofile import get_agent_profile as crud_get_agent_profile
from app.crud.agentprofile import get_agent_profiles as crud_get_agent_profiles
from app.crud.agentprofile import get_profiles_with_agents as crud_get_profiles_with_agents
from app.crud.agentprofile import get_rules_by_agentprofile as crud_get_rules_by_agentprofile
from app.crud.agentprofile import get_agents_by_profile_id as crud_get_agents_by_profile_id
# from app.crud.agent import get_agents_by_profile as crud_get_agents_by_profile
from app.schemas.agentprofile import AgentProfileCreate
from app import dependencies
from typing import List
from app.models.user import User
from app.oauth_user import get_current_user

router = APIRouter()

@router.post("/agentprofiles/")
def create_agent_profile(agent_profile: AgentProfileCreate, agent_ids: List[int], db: Session = Depends(dependencies.get_db), current_user: User = Depends(get_current_user)):
    return crud_create_agent_profile(db, agent_profile, agent_ids)

@router.get("/agentprofiles/{agent_profile_id}")
def read_agent_profile(agent_profile_id: int, db: Session = Depends(dependencies.get_db), current_user: User = Depends(get_current_user)):
    agent_profile = crud_get_agent_profile(db, agent_profile_id)
    if agent_profile is None:
        raise HTTPException(status_code=404, detail="Agent Profile not found")
    return agent_profile

@router.get("/agentprofiles/")
def read_agent_profiles(skip: int = 0, limit: int = 10, db: Session = Depends(dependencies.get_db), current_user: User = Depends(get_current_user)):
    agent_profiles = crud_get_agent_profiles(db, skip, limit)
    return agent_profiles

@router.get("/allprofilesagent/")
def read_agent_profiles(skip: int = 0, limit: int = 10, db: Session = Depends(dependencies.get_db), current_user: User = Depends(get_current_user)):
    agent_profiles = crud_get_profiles_with_agents(db, skip, limit)
    return agent_profiles

@router.get("/rules_by_agent_profile/{agentprofile_id}/")
def read_rules_by_agent(agentprofile_id: int, db: Session = Depends(dependencies.get_db), current_user: User = Depends(get_current_user)):
    rules = crud_get_rules_by_agentprofile(db, agentprofile_id)
    agents = crud_get_agents_by_profile_id(db, agentprofile_id)
    return {"rules":rules,"agents": agents}

@router.post("/schedule/{agent_profile_id}/rule-run")
async def schedule_rule_run(agent_profile_id, time, date, frequency):
    start_date:str = agent_profile_id
    time:object = time
    frequency:str = frequency
    # schedule_rule_run(agent_profile_id, time, date, frequency):\
    return {"result":"succesfully scheduled rules"}