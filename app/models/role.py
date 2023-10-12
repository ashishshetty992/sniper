from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import relationship
from app.database import Base

class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, index=True)

    # Define the many-to-many relationship with users
    users = relationship("User", secondary="user_roles", back_populates="roles")
