from sqlalchemy.orm import Session
from app.models.agent import Agent
from app.schemas.agent import AgentCreate
from sqlalchemy.orm import joinedload
import pdb

def create_agent(db: Session, agent: AgentCreate):
    db_agent = Agent(**agent.dict())
    db.add(db_agent)
    db.commit()
    db.refresh(db_agent)
    return db_agent

def get_agent(db: Session, agent_id: int):
    return db.query(Agent).filter(Agent.id == agent_id).first()

def get_agents(db: Session, skip: int = 0, limit: int = 10):
    return db.query(Agent).offset(skip).limit(limit).all()

def get_agents_with_profiles(db: Session, skip: int = 0, limit: int = 10):
    # Query the Agent model, specifying a join to the AgentProfile model using the 'agents' relationship
    agents = (
        db.query(Agent)
        .options(joinedload(Agent.profiles))  # Use joinedload to eagerly load agent profiles
        .offset(skip)
        .limit(limit)
        .all()
    )
    return agents