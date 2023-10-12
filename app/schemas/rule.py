# schemas/rule.py
from pydantic import BaseModel
from datetime import datetime

class RuleBase(BaseModel):
    name: str
    exec_rule: str

class RuleCreate(RuleBase):
    pass

class Rule(RuleBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True
