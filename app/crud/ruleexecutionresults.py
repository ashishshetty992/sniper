from sqlalchemy.orm import Session
from sqlalchemy.orm import joinedload

from app.models.rule_execution_result import RuleExecutionResult
from app.models.agent import Agent
from app.models.rule import Rule
from app.models.schedule import Schedule
import pdb

def get_all_rule_execution_results(db: Session, skip: int = 0, limit: int = 10000, rule_id =None, agent_id=None, schedule_id=None):
    db_query =  db.query(RuleExecutionResult).options(joinedload(RuleExecutionResult.agent)).options(joinedload(RuleExecutionResult.rule)).options(joinedload(RuleExecutionResult.schedule))
    # pdb.set_trace()
    if (rule_id):
        db_query = db_query.filter(Rule.id == rule_id)
    if agent_id:
        db_query = db_query.filter(Agent.id == agent_id)
    if schedule_id:
        db_query = db_query.filter(Schedule.id == schedule_id)
    results = (
       db_query.offset(skip)
        .limit(limit)
        .all()
    )
    return results