from enum import Enum

class References(Enum):
    AGENT="agent"
    AGENTPROFILE = "agent_profile"
    RULE = "rule"


class ScheduledStatus(Enum):
    CREATED = 'created'
    SCHEDULED = 'scheduled'
    RUNNING = 'running'
    EXECUTED = 'executed'