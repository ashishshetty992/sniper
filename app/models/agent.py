# models/agent.py
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Table
from sqlalchemy.orm import relationship
from app.database import Base
from datetime import datetime
from app.models.agent_profile_association import agent_profile_association  # Import the association table


class Agent(Base):
    __tablename__ = "agents"

    id = Column(Integer, primary_key=True, index=True)
    agent_name = Column(String(255), unique=True, index=True) # agent identifier name for better readability
    name = Column(String(255), index=True)
    ip_address = Column(String(255))
    active = Column(Boolean, default=True,  index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)
    
    # Add a reference to the AgentProfiles that reference this agent
    profiles = relationship("AgentProfile", secondary="agent_profile_association", back_populates="agents")
    rules = relationship("Rule", secondary="rule_agent_association", back_populates="agents")

