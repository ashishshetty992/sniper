from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from app.crud.agent import create_agent as crud_create_agent
from app.crud.agent import get_agent as crud_get_agent
from app.crud.agent import get_agents as crud_get_agents
from app.crud.agent import get_agents_with_profiles as crud_get_agents_with_profiles
from app.crud.agent import get_rules_by_agent as crud_get_rules_by_agent
from app.schemas.agent import AgentCreate
from app.helpers import ssh_helper
from app import dependencies
from app.helpers.jobs import ssh_key_generation_job_scheduler

router = APIRouter()

@router.post("/agents/")
def create_agent(agent: AgentCreate, db: Session = Depends(dependencies.get_db)):
    try:
        return crud_create_agent(db, agent)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/agents/{agent_id}")
def read_agent(agent_id: int, db: Session = Depends(dependencies.get_db)):
    agent = crud_get_agent(db, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent

@router.get("/agents/")
def read_agents(skip: int = 0, limit: int = 10, db: Session = Depends(dependencies.get_db)):
    agents = crud_get_agents(db, skip, limit)
    return agents

@router.get("/allagentprofiles/")
def read_agent_profiles(skip: int = 0, limit: int = 10, db: Session = Depends(dependencies.get_db)):
    agent_profiles = crud_get_agents_with_profiles(db, skip, limit)
    return agent_profiles

@router.get("/rules_by_agent/{agent_id}/")
def read_rules_by_agent(agent_id: int, db: Session = Depends(dependencies.get_db)):
    rules = crud_get_rules_by_agent(db, agent_id)
    return rules

# @router.get("/agents/{agent_id}/rules/")
# def read_rules_by_agent(agent_id: int, db: Session = Depends(dependencies.get_db)):
#     rules = crud_get_rules_by_agent(db, agent_id)
#     return rules

# @router.get("/agents/{agent_id}/rules/{rule_id}/")



@router.post("/heartbeatcheck/")
async def check_heartbeat(request: Request):
    try:
        data = await request.json()
        hostname = data.get("hostname")
        username = data.get("username")
        ssh_client = ssh_helper.connect_to_agent(hostname, username)
        ssh_client.close()
        return {"result":"connection was succesful"}
    except Exception:
        raise HTTPException(status_code=400, detail=f"Failed to make connection to the agent {hostname}")


@router.post("/searchfiles/")
async def search_files(request: Request):
    data = await request.json()
    hostname = data.get("hostname")
    username = data.get("username")
    extension = data.get("extension")
    result = ssh_helper.search_file_extension_in_remote(hostname, username, extension)
    return {"result":result}

@router.post("/schedule/ssh-key-regeneration")
async def schedule_ssh_key_regeneration(request: Request):
    data = await request.json()
    start_date:str = data.get("start_date")
    time:object = data.get("time")
    frequency:str = data.get("frequency")
    ssh_key_generation_job_scheduler(start_date, time, frequency)
    return {"result":"scheduled ssh regeneration job"}