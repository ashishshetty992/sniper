# models/agent_profile.py
from sqlalchemy import Column, Integer, String, DateTime, TEXT
from app.database import Base
from datetime import datetime
from sqlalchemy.orm import relationship
from app.database import Base
from app.models.agent_profile_association import agent_profile_association  # Import the association table

class RuleExecutionResult(Base):
    __tablename__ = "rule_execution_result"

    id = Column(Integer, primary_key=True, index=True)
    results = Column(TEXT)
    latency = Column(Integer, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)
    status = Column(String(255), index=True)
    # Add a reference to the Agents that are associated with this profile
    agent = relationship("Agent", secondary="agent_rule_exec_association")

    rule = relationship("Rule", secondary="rule_to_rule_exec_association")

    schedule = relationship("Schedule", secondary="schedule_rule_exec_association")