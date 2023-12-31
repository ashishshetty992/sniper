from sqlalchemy.orm import Session
from app.models.agent import Agent
from app.schemas.agent import AgentCreate
from app.schemas.agent import AgentUpdate
from sqlalchemy.orm import joinedload
from app.helpers.ssh_helper import make_ssh_connection
import pdb

def create_agent(db: Session, agent: AgentCreate):
    # creat ssh connection and then save only if it succeeds
    make_ssh_connection(agent.ip_address, agent.name, agent.password)
    del agent.password
    print("-------- after ssh connection -------")
    db_agent = Agent(**agent.dict())
    db.add(db_agent)
    db.commit()
    db.refresh(db_agent)
    return db_agent

def get_agent(db: Session, agent_id: int):
    return db.query(Agent).filter(Agent.id == agent_id).first()

def get_agents(db: Session, skip: int = 0, limit: int = 1000):
    return db.query(Agent).filter(Agent.active ==True).offset(skip).limit(limit).all()

def get_agents_with_profiles(db: Session, skip: int = 0, limit: int = 1000):
    # Query the Agent model, specifying a join to the AgentProfile model using the 'agents' relationship
    agents = (
        db.query(Agent).filter(Agent.active ==True)
        .options(joinedload(Agent.profiles))  # Use joinedload to eagerly load agent profiles
        .offset(skip)
        .limit(limit)
        .all()
    )
    return agents

def get_rules_by_agent(db: Session, agent_id: int):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if(not agent): raise Exception(f"Agent not present for the id : {agent_id}")
    return agent


def update_agent(db: Session, agent_id: int, agent_update: AgentUpdate):
    db_agent = db.query(Agent).filter(Agent.id == agent_id).filter(Agent.active ==True).first()
    if db_agent:
        # Update agent attributes
        for key, value in agent_update.dict().items():
            setattr(db_agent, key, value)

        db.commit()
        db.refresh(db_agent)

    return db_agent

def get_agents_by_profile(db: Session, agent_profile_id:int):
    agents = (
        db.query(Agent).filter(Agent.profiles == agent_profile_id).filter(Agent.active ==True).all()
    )
    return agents
