from sqlalchemy import Table, Column, Integer, ForeignKey
from app.database import Base

# Define the agent_profile_association table, if not already defined
agent_profile_association = Table(
    "agent_profile_association",
    Base.metadata,
    Column("agent_id", Integer, ForeignKey("agents.id"), primary_key=True),
    Column("profile_id", Integer, ForeignKey("agent_profiles.id"), primary_key=True),
    extend_existing=True
)

# Define the association table for rules and agent profiles
rule_profile_association = Table(
    "rule_profile_association",
    Base.metadata,
    Column("rule_id", Integer, ForeignKey("rules.id")),
    Column("profile_id", Integer, ForeignKey("agent_profiles.id")),
)

# Define the association table for rules and agents
rule_agent_association = Table(
    "rule_agent_association",
    Base.metadata,
    Column("rule_id", Integer, ForeignKey("rules.id")),
    Column("agent_id", Integer, ForeignKey("agents.id")),
)

agent_rule_exec_association = Table(
    "agent_rule_exec_association",
    Base.metadata,
    Column("rule_exec_id", Integer, ForeignKey("rule_execution_result.id")),
    Column("agent_id", Integer, ForeignKey("agents.id")),
)

rule_to_rule_exec_association =  Table(
    "rule_to_rule_exec_association",
    Base.metadata,
    Column("rule_exec_id", Integer, ForeignKey("rule_execution_result.id")),
    Column("rule_id", Integer, ForeignKey("rules.id")),
)