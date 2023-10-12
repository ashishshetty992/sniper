# models/agent_profile.py
from sqlalchemy import Column, Integer, String, DateTime, Table, ForeignKey
from app.database import Base
from datetime import datetime
from sqlalchemy.orm import relationship
from app.database import Base
from app.models.agent_profile_association import agent_profile_association  # Import the association table

class AgentProfile(Base):
    __tablename__ = "agent_profiles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)
    
    # Add a reference to the Agents that are associated with this profile
    agents = relationship("Agent", secondary="agent_profile_association")

    rules = relationship("Rule", secondary="rule_profile_association")
