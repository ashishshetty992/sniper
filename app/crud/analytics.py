from sqlalchemy.orm import Session
from typing import List
from sqlalchemy.orm import joinedload
import pdb

from app.models.agent import Agent
from app.models.agentprofile import AgentProfile
from app.models.rule import Rule
from app.models.schedule import Schedule


def get_analytics_data(db: Session):
    agent_count = db.query(Agent).count()
    agent_profile_count = db.query(AgentProfile).count()
    schedule_count = db.query(Schedule).count()
    rule_count = db.query(Rule).count()
    return {'agent_count':agent_count, 'agent_profile_count':agent_profile_count, "schedule_count":schedule_count, 'rule_count':rule_count}





