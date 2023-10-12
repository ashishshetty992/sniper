from sqlalchemy.orm import Session
from app.models.agent import Agent
from app.schemas.agent import AgentCreate
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
