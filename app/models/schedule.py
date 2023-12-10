# models/rule.py
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Table
from sqlalchemy.orm import relationship
from app.database import Base
from datetime import datetime
from app.models.agent_profile_association import rule_agent_association  # Import the association table
from app.models.agent_profile_association import rule_profile_association  # Import the association table


class Schedule(Base):
    __tablename__ = "schedules"

    id = Column(Integer, primary_key=True, index=True)
    time = Column(String(255))
    start_date = Column(String(255))
    frequency = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)
    
    # Add a reference to the AgentProfiles that reference this rule
    agent_profiles = relationship("AgentProfile", secondary="rule_profile_association")
    agents = relationship("Agent", secondary="rule_agent_association")
