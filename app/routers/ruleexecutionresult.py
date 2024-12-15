from app.crud.ruleexecutionresults import get_all_rule_execution_results
from sqlalchemy.orm import Session
from fastapi import APIRouter, Depends
from app import dependencies
from app.models.user import User
from app.oauth_user import get_current_user

router = APIRouter()

@router.get("/rule-execution-results")
def fetch_all_rule_results(skip: int = 0, limit: int = 1000, rule_id:int = None, agent_id:int = None,  schedule_id:int = None, db: Session = Depends(dependencies.get_db)):
    results = get_all_rule_execution_results(db, skip, limit, rule_id, agent_id, schedule_id)
    return results