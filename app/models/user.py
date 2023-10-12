from sqlalchemy import Column, Integer, String, Table, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from app.database import Base
import bcrypt
from typing import Union
from sqlalchemy.orm import Mapped


# Define the association table
user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id"), primary_key=True),
    Column("role_id", Integer, ForeignKey("roles.id"), primary_key=True),
)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, index=True)
    email = Column(String(255), unique=True, index=True)
    full_name = Column(String(255))
    password = Column(String(60))  # Store the hashed password
    disabled: Mapped[bool] = None  # Use Mapped to specify the type
    is_superadmin: Mapped[bool] = None

    # Define the many-to-many relationship with roles
    roles = relationship("Role", secondary=user_roles, back_populates="users")

    def set_password(self, password: str):
        self.password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    def check_password(self, password: str):
        return bcrypt.checkpw(password.encode("utf-8"), self.password.encode("utf-8"))
