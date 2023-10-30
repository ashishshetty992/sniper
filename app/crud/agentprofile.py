from sqlalchemy.orm import Session
from app.models.agentprofile import AgentProfile
from app.models.agent import Agent
from app.schemas.agentprofile import AgentProfileCreate
from typing import List
from sqlalchemy.orm import joinedload

def create_agent_profile(db: Session, agent_profile: AgentProfileCreate, agent_ids: List[int]):
    db_agent_profile = AgentProfile(**agent_profile.dict())
    for agent_id in agent_ids:
        agent = db.query(Agent).filter(Agent.id == agent_id).first()
        if agent:
            db_agent_profile.agents.append(agent)
    db.add(db_agent_profile)
    db.commit()
    db.refresh(db_agent_profile)
    return db_agent_profile

def get_agent_profile(db: Session, agent_profile_id: int):
    return db.query(AgentProfile).filter(AgentProfile.id == agent_profile_id).first()

def get_agent_profiles(db: Session, skip: int = 0, limit: int = 10):
    return db.query(AgentProfile).offset(skip).limit(limit).all()


def get_profiles_with_agents(db: Session, skip: int = 0, limit: int = 10):
    # Query the Agent model, specifying a join to the AgentProfile model using the 'agents' relationship
    profile = (
        db.query(AgentProfile)
        .options(joinedload(AgentProfile.agents))  # Use joinedload to eagerly load agent profiles
        .offset(skip)
        .limit(limit)
        .all()
    )
    return profile