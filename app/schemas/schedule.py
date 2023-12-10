from pydantic import BaseModel

from app.enums import References


class ScheduleBase(BaseModel):
    start_date: str
    time: tuple
    frequency: str


class RuleRunSchedule(ScheduleBase):
    reference: References
    time: tuple
    frequency: str