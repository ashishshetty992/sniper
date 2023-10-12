from pydantic import BaseModel
from typing import List

class RoleResponse(BaseModel):
    id: int
    name: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    roles: List[RoleResponse]

class TokenResponse(BaseModel):
    access_token: str
    token_type: str

class AgentProfileResponseModel(BaseModel):
    id: int
    name: str

class AgentResponseModel(BaseModel):
    id: int
    name: str

class RuleResponseModel(BaseModel):
    id: int
    name: str