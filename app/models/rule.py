# models/rule.py
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Table
from sqlalchemy.orm import relationship
from app.database import Base
from datetime import datetime
from app.models.agent_profile_association import rule_agent_association  # Import the association table
from app.models.agent_profile_association import rule_profile_association  # Import the association table


class Rule(Base):
    __tablename__ = "rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), index=True)
    exec_rule = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)
    
    # Add a reference to the AgentProfiles that reference this rule
    agent_profiles = relationship("AgentProfile", secondary="rule_profile_association")
    agents = relationship("Agent", secondary="rule_agent_association")
