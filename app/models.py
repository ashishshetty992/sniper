from sqlalchemy import Column, Integer, String, ForeignKey, Boolean, Table
from sqlalchemy.orm import relationship
from sqlalchemy.sql import expression
from app.database import Base


class Admin(Base):
    __tablename__ = "admins"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, index=True)
    email = Column(String(255), unique=True, index=True)
    full_name = Column(String(255))
    # Add more fields as needed, such as password hashing, roles, etc.

# Define User-Role Many-to-One Relationship
user_role_association = Table(
    'user_role_association',
    Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id')),
    Column('role_id', Integer, ForeignKey('roles.id'))
)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, index=True)
    password = Column(String(255))
    email = Column(String(255), unique=True, index=True)
    full_name = Column(String(255))
    is_admin = Column(Boolean, server_default=expression.false(), nullable=False)

    roles = relationship("Role", secondary=user_role_association, back_populates="users")

class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, index=True)

    users = relationship("User", secondary=user_role_association, back_populates="roles")

class Agent(Base):
    __tablename__ = "agents"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(255), unique=True, index=True)
    # Add other agent-related fields here

    # Relationship with Profile
    profiles = relationship("Profile", back_populates="agent")

class Rule(Base):
    __tablename__ = "rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, index=True)
    content = Column(String(255))
    # Add other rule-related fields here

    # Relationship with Profile
    profiles = relationship("Profile", back_populates="rules")

class Profile(Base):
    __tablename__ = "profiles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, index=True)
    # Add other profile-related fields here

    # Relationship with Agent
    agent_id = Column(Integer, ForeignKey("agents.id"))
    agent = relationship("Agent", back_populates="profiles")

    # Relationship with Rule
    rules = relationship("Rule", back_populates="profiles")
