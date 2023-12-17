from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.crud.rule import create_rule as crud_create_rule
from app.crud.rule import get_rule as crud_get_rule
from app.crud.rule import get_rules as crud_get_rules
# from app.crud.rule import execute_rule_by_id as execute_rule_by_id
from app.crud.rule import get_rules_with_agents_and_profile as crud_get_rules_with_agents_and_profile
from app.schemas.rule import RuleCreate
from app.models.response import RuleResponseModel
from app import dependencies
from app.dependencies import get_db
from typing import List
from app.models.user import User
from app.models.role import Role
from app.oauth_user import get_current_user
from app.routers.user import get_current_user_details
import pdb

router = APIRouter()

@router.post("/rules/")
def create_rule(rule: RuleCreate, agent_ids: List[int], agent_profile_ids: List[int], db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    current_user_details = get_current_user_details(db, current_user.username)
    return crud_create_rule(db, rule, agent_ids, agent_profile_ids)

@router.get("/rules/{rule_id}")
def read_rule(rule_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    rule = crud_get_rule(db, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule

@router.get("/rules/")
def read_rules(skip: int = 0, limit: int = 10, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    rules = crud_get_rules(db, skip, limit)
    return rules

@router.get("/get_rules_with_agents_and_profile/")
def read_rules(skip: int = 0, limit: int = 10, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    rules = crud_get_rules_with_agents_and_profile(db, skip, limit)
    return rules

# @router.get("/rule_agents_profiles/{rule_id}")
# def get_agents_profiles_on_rules(rule_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
#     rule = (db, rule_id)
#     if rule is None:
#         raise HTTPException(status_code=404, detail="Rule not found")
#     return rule
