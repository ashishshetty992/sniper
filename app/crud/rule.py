from sqlalchemy.orm import Session
from app.models.rule import Rule
from app.schemas.rule import RuleCreate
from app.schemas.rule import RuleUpdate
from typing import List
from app.models.agent import Agent
from app.models.agentprofile import AgentProfile
import pdb
from sqlalchemy.orm import joinedload

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

def update_rule(db: Session, rule_id: int, rule_update: RuleUpdate, agent_ids: List[int], agent_profile_ids: List[int]):
    db_rule = db.query(Rule).filter(Rule.id == rule_id).first()

    if db_rule:
        # Update rule attributes
        for key, value in rule_update.dict().items():
            setattr(db_rule, key, value)

        # Clear existing agents and add new ones
        db_rule.agents = []
        for agent_id in agent_ids:
            agent = db.query(Agent).filter(Agent.id == agent_id).first()
            if agent:
                db_rule.agents.append(agent)

        # Clear existing agent profiles and add new ones
        db_rule.agent_profiles = []
        for agent_profile_id in agent_profile_ids:
            agent_profile = db.query(AgentProfile).filter(AgentProfile.id == agent_profile_id).first()
            if agent_profile:
                db_rule.agent_profiles.append(agent_profile)

        db.commit()
        db.refresh(db_rule)

    return db_rule

def get_rule(db: Session, rule_id: int):
    return db.query(Rule).filter(Rule.id == rule_id).first()

def get_rules(db: Session, skip: int = 0, limit: int = 10):
    return db.query(Rule).offset(skip).limit(limit).all()


def get_rules_with_agents_and_profile(db: Session, skip: int = 0, limit: int = 10):
    # Query the Agent model, specifying a join to the AgentProfile model using the 'agents' relationship
    rules = (
        db.query(Rule)
        .options(joinedload(Rule.agents))  # Use joinedload to eagerly load agent profiles
        .options(joinedload(Rule.agent_profiles))  # Use joinedload to eagerly load agent profiles
        .offset(skip)
        .limit(limit)
        .all()
    )
    return rules

def get_rules_for_agent(db: Session, agent_id:int):
    # Query the Agent model, specifying a join to the AgentProfile model using the 'agents' relationship
    return db.query(Rule).filter(Agent.id == agent_id)


def get_all_agents_and_rule_by_rule_id(db:Session, rule_id:int):
    rule = db.query(Rule).filter(Rule.id == rule_id).first()
    # get all the agents and agent profile attached to the rule
    agents = rule.agents
    agent_ids = [ agent.id for agent in agents]
    agent_profile = rule.agent_profiles
    for profile in agent_profile:
        profile_agents = profile.agents
        for agent in profile_agents:
            if agent.id not in agent_ids:
                agents.extend(agent)
    return [agents, rule]