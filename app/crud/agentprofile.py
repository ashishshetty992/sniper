from sqlalchemy.orm import Session
from app.models.agentprofile import AgentProfile
from app.models.agent import Agent
from app.schemas.agentprofile import AgentProfileCreate
from app.schemas.agentprofile import AgentProfileUpdate
from typing import List
from sqlalchemy.orm import joinedload

def create_agent_profile(db: Session, agent_profile: AgentProfileCreate, agent_ids: List[int]):
    db_agent_profile = AgentProfile(**agent_profile.dict())
    for agent_id in agent_ids:
        agent = db.query(Agent).filter(Agent.id == agent_id).filter(Agent.active ==True).first()
        if agent:
            db_agent_profile.agents.append(agent)
    db.add(db_agent_profile)
    db.commit()
    db.refresh(db_agent_profile)
    return db_agent_profile

def get_agent_profile(db: Session, agent_profile_id: int):
    return db.query(AgentProfile).filter(AgentProfile.id == agent_profile_id).first()

def get_agent_profiles(db: Session, skip: int = 0, limit: int = 1000):
    return db.query(AgentProfile).filter(AgentProfile.active ==True).offset(skip).limit(limit).all()

def get_rules_by_agentprofile(db: Session, agent_profile_id: int):
    agent_profile = db.query(AgentProfile).filter(AgentProfile.id == agent_profile_id).first()
    rules = agent_profile.rules
    return rules

def get_profiles_with_agents(db: Session, skip: int = 0, limit: int = 1000):
    # Query the Agent model, specifying a join to the AgentProfile model using the 'agents' relationship
    profile = (
        db.query(AgentProfile).filter(AgentProfile.active ==True)
        .options(joinedload(AgentProfile.agents))  # Use joinedload to eagerly load agent profiles
        .offset(skip)
        .limit(limit)
        .all()
    )
    return profile

def get_agents_by_profile_id(db: Session, profile_id: int):
    # Query the AgentProfile model based on the given profile_id
    agent_profile = db.query(AgentProfile).filter(AgentProfile.id == profile_id).first()

    if agent_profile:
        # Access the 'agents' attribute to get the agents associated with the agent profile
        agents = agent_profile.agents
        return agents

    return None


def update_agent_profile(db: Session, profile_id: int, profile_update: AgentProfileUpdate, agent_ids: List[int]):
    db_agent_profile = db.query(AgentProfile).filter(AgentProfile.id == profile_id).filter(AgentProfile.active ==True).first()

    if db_agent_profile:
        for key, value in profile_update.dict().items():
            setattr(db_agent_profile, key, value)

        # Clear existing agents and add new ones
        db_agent_profile.agents = []
        for agent_id in agent_ids:
            agent = db.query(Agent).filter(Agent.id == agent_id).filter(AgentProfile.active ==True).first()
            if agent:
                db_agent_profile.agents.append(agent)

        db.commit()
        db.refresh(db_agent_profile)

    return db_agent_profile