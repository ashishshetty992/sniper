# schemas/agent.py
from pydantic import BaseModel
from datetime import datetime

class AgentBase(BaseModel):
    name: str
    ip_address: str
    password: str
    active: bool

class AgentCreate(AgentBase):
    pass

class Agent(AgentBase):
    id: int
    unique_id: str
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True
