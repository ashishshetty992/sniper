from pydantic import BaseModel

from app.enums import References


class ScheduleBase(BaseModel):
    start_date: str # (Y-m-d)
    hour: int
    minutes: int
    frequency: str
    reference: str
    reference_id: int


class RuleRunSchedule(ScheduleBase):
    reference: References
    time: tuple
    frequency: str

class ScheduleCreate(ScheduleBase):
    pass