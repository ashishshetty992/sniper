from pydantic import BaseModel
from typing import List, Optional

# Schema for Role
class RoleBase(BaseModel):
    name: str

class RoleCreate(RoleBase):
    pass

class Role(RoleBase):
    id: int

    class Config:
        orm_mode = True

# Schema for Admin
class AdminBase(BaseModel):
    username: str

class AdminCreate(AdminBase):
    password: str
    is_superadmin: bool  # Include a field to specify superadmin status

class Admin(AdminBase):
    id: int
    is_superadmin: bool

    class Config:
        orm_mode = True

class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str
    is_admin: bool

class User(UserBase):
    id: int
    roles: List[Role] = []

    class Config:
        orm_mode = True

# Schema for Agent
class AgentBase(BaseModel):
    ip_address: str

class AgentCreate(AgentBase):
    pass

class Agent(AgentBase):
    id: int
    profiles: List["Profile"] = []

    class Config:
        orm_mode = True

# Schema for Rule
class RuleBase(BaseModel):
    name: str
    content: str

class RuleCreate(RuleBase):
    pass

class Rule(RuleBase):
    id: int
    profiles: List["Profile"] = []

    class Config:
        orm_mode = True

# Schema for Profile
class ProfileBase(BaseModel):
    name: str

class ProfileCreate(ProfileBase):
    pass

class Profile(ProfileBase):
    id: int
    agent: Agent
    rules: List[Rule] = []

    class Config:
        orm_mode = True
