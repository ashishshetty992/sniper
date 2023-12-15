# schemas/agent_profile.py
from pydantic import BaseModel
from datetime import datetime

class AgentProfileBase(BaseModel):
    name: str

class AgentProfileCreate(AgentProfileBase):
    pass


class AgentProfileUpdate(AgentProfileBase):
    pass

class AgentProfile(AgentProfileBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True
