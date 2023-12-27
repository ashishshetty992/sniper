# schemas/agent_profile.py
from pydantic import BaseModel
from datetime import datetime

class AgentProfileBase(BaseModel):
    name: str
    active: bool

class AgentProfileCreate(AgentProfileBase):
    pass


class AgentProfileUpdate(BaseModel):
    name: str
    active: bool

class AgentProfile(AgentProfileBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True
