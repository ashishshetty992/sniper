from typing import List
from app.models.role import Role  # Import the Role model
from pydantic import BaseModel, BaseConfig
from typing import List
from typing import Union


# Configure Pydantic to allow arbitrary types
class CustomBaseConfig(BaseConfig):
    arbitrary_types_allowed = True

class UserBase(BaseModel):
    username: str
    email: str
    full_name: str
    disabled: bool
    is_superadmin: bool


class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int
    roles: List[str]  # Use 'Role' as a string to avoid circular import issues

    class Config:
        orm_mode = True
