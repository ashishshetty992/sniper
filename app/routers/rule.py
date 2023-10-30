from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.crud.rule import create_rule as crud_create_rule
from app.crud.rule import get_rule as crud_get_rule
from app.crud.rule import get_rules as crud_get_rules
from app.crud.rule import get_rules_with_agents_and_profile as crud_get_rules_with_agents_and_profile
from app.schemas.rule import RuleCreate
from app.models.response import RuleResponseModel
from app import dependencies
from typing import List

router = APIRouter()

@router.post("/rules/", response_model=RuleResponseModel)
def create_rule(rule: RuleCreate, agent_ids: List[int], agent_profile_ids: List[int], db: Session = Depends(dependencies.get_db)):
    return crud_create_rule(db, rule, agent_ids, agent_profile_ids)

@router.get("/rules/{rule_id}", response_model=RuleResponseModel)
def read_rule(rule_id: int, db: Session = Depends(dependencies.get_db)):
    rule = crud_get_rule(db, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule

@router.get("/rules/", response_model=List[RuleResponseModel])
def read_rules(skip: int = 0, limit: int = 10, db: Session = Depends(dependencies.get_db)):
    rules = crud_get_rules(db, skip, limit)
    return rules

@router.get("/get_rules_with_agents_and_profile/")
def read_rules(skip: int = 0, limit: int = 10, db: Session = Depends(dependencies.get_db)):
    rules = crud_get_rules_with_agents_and_profile(db, skip, limit)
    return rules