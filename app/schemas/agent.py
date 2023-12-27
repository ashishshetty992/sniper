# schemas/agent.py
from pydantic import BaseModel
from datetime import datetime

class AgentBase(BaseModel):
    name: str
    agent_name: str
    ip_address: str
    password: str
    active: bool

class AgentCreate(AgentBase):
    pass

class AgentUpdate(BaseModel):
    agent_name: str
    active: bool
    updated_at: datetime

class Agent(AgentBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True
