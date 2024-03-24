# schemas/rule.py
from pydantic import BaseModel
from datetime import datetime

class RuleBase(BaseModel):
    name: str
    category:str
    sub_category:str
    exec_rule: str
    path:str

class RuleCreate(RuleBase):
    exec_rule: str = ""
    pass

class RuleUpdate(BaseModel):
    name:str
    path:str
    category:str
    sub_category:str

class Rule(RuleBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True
