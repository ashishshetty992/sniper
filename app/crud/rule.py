from sqlalchemy.orm import Session
from app.models.rule import Rule
from app.schemas.rule import RuleCreate
from typing import List
from app.models.agent import Agent
from app.models.agentprofile import AgentProfile
import pdb

def create_rule(db: Session, rule: RuleCreate, agent_ids: List[int], agent_profile_ids: List[int]):
    db_rule = Rule(**rule.dict())
    for agent_id in agent_ids:
        agent = db.query(Agent).filter(Agent.id == agent_id).first()
        if agent:
            db_rule.agents.append(agent)
    for agent_profile_id in agent_profile_ids:
        agent_profile = db.query(AgentProfile).filter(AgentProfile.id == agent_profile_id).first()
        if agent_profile:
            db_rule.agent_profiles.append(agent_profile)
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)
    return db_rule

def get_rule(db: Session, rule_id: int):
    return db.query(Rule).filter(Rule.id == rule_id).first()

def get_rules(db: Session, skip: int = 0, limit: int = 10):
    return db.query(Rule).offset(skip).limit(limit).all()
