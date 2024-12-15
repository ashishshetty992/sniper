from fastapi import APIRouter, Depends, Form, HTTPException, UploadFile, File
from pydantic import Json
from sqlalchemy.orm import Session
from app.crud.analytics import get_analytics_data
from app.crud.rule import create_rule as crud_create_rule
from app.crud.rule import get_rule as crud_get_rule
from app.crud.rule import get_rules as crud_get_rules
from app.crud.rule import update_rule as crud_update_rules
from app.crud.rule import get_rules_with_agents_and_profile_by_rule_id as crud_get_rules_with_agents_and_profile_by_rule_id
from app.crud.rule import get_rules_with_agents_and_profile as crud_get_rules_with_agents_and_profile
from app.crud.analytics import get_analytics_data as get_analytics_data
from app.schemas.rule import RuleCreate, RuleUpdate
from app.models.response import RuleResponseModel
from app import dependencies
from app.dependencies import get_db
from typing import List
from app.models.user import User
from app.models.role import Role
from app.oauth_user import get_current_user
from app.routers.user import get_current_user_details
from app.helpers.ssh_helper import execute_rule_in_remote
import pdb
import asyncio

router = APIRouter()

@router.post("/rules/")
def create_rule(rule: RuleCreate = Depends(), agent_ids: List[int]=[], agent_profile_ids: List[int]=[], db: Session = Depends(get_db), current_user: User = Depends(get_current_user), rule_file: List[UploadFile] = File(...)):
    current_user_details = get_current_user_details(db, current_user.username)
    return crud_create_rule(db, rule, agent_ids, agent_profile_ids, rule_file)

@router.get("/rules/{rule_id}")
def read_rule(rule_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    rule = crud_get_rule(db, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule

@router.get("/get_rules_with_agents_and_profile_by_rule_id/{rule_id}")
def read_rule(rule_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    rule = crud_get_rules_with_agents_and_profile_by_rule_id(db, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule

@router.get("/rules/")
def read_rules(skip: int = 0, limit: int = 1000, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    rules = crud_get_rules(db, skip, limit)
    return rules

@router.get("/get_rules_with_agents_and_profile/")
def read_rules(skip: int = 0, limit: int = 1000, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    rules = crud_get_rules_with_agents_and_profile(db, skip, limit)
    analytics_data = get_analytics_data(db)
    return rules

@router.put("/rules/{rule_id}")
def update_rule(rule_id: int,  rule_update: RuleUpdate, agent_ids:List[int], agent_profile_ids:List[int],db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    rule = crud_update_rules(db, rule_id, rule_update, agent_ids, agent_profile_ids)
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule

@router.get("/get_analytics_data/")
def get_analytics(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    data = get_analytics_data(db)
    if data is None:
        raise HTTPException(status_code=404, detail="Analytics Not found")
    return data

async def execute_rule_async(agent, rule):
    try:
        logger.info(f"Executing rule on agent {agent.id} with name {agent.name}")
        logger.info(f"Rule file: {rule.exec_rule}")
        # Execute rule immediately using ssh_helper
        result = await asyncio.to_thread(execute_rule_in_remote,
                                         hostname=agent.ip_address,
                                         username=agent.agent_name,
                                         rule_file=rule.exec_rule)

        logger.info(f"Execution result: {result}")
        # Process the execution result
        if isinstance(result, dict) and result.get('status') == 'success':
            return {
                "agent_id": agent.id,
                "agent_name": agent.name,
                "status": "success",
                "matches": result.get('matches', []),
                "scan_time": result.get('scan_time'),
                "files_scanned": result.get('files_scanned')
            }
        else:
            return {
                "agent_id": agent.id,
                "agent_name": agent.name,
                "status": "error",
                "error": str(result) if result else "Unknown error occurred"
            }
    except Exception as e:
        return {
            "agent_id": agent.id,
            "agent_name": agent.name,
            "status": "error",
            "error": str(e)
        }

@router.post("/rules/{rule_id}/scan")
async def scan_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Immediately execute a rule on all associated agents
    """
    # Get rule and its agents
    rule_data = crud_get_rules_with_agents_and_profile_by_rule_id(db, rule_id)
    print(rule_data)
    if not rule_data['rule']:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    rule = rule_data['rule']
    
    # Execute rule for each associated agent concurrently
    tasks = [execute_rule_async(agent, rule) for agent in rule.agents]
    results = await asyncio.gather(*tasks)
    
    return {
        "rule_id": rule_id,
        "rule_name": rule.name,
        "execution_results": results
    }

# @router.get("/rule_agents_profiles/{rule_id}")
# def get_agents_profiles_on_rules(rule_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
#     rule = (db, rule_id)
#     if rule is None:
#         raise HTTPException(status_code=404, detail="Rule not found")
#     return rule
