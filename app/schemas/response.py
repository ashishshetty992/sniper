from pydantic import BaseModel
from typing import List
from app.models.response import RoleResponse, UserResponse
import typing
from pydantic import BaseModel

class RoleResponseSchema(BaseModel):
    id: int
    name: str

class UserResponseSchema(BaseModel):
    id: int
    username: str
    is_superadmin: bool
    roles: List[RoleResponseSchema]

# class AdminResponseSchema(BaseModel):
#     id: int
#     username: str

# class AdminResponseSchema(BaseModel):
#     id: int
#     username: str

class TokenResponseSchema(BaseModel):
    access_token: str
    token_type: str