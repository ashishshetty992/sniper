from sqlalchemy.orm import Session
from app.models.schedule import Schedule
from app.schemas.schedule import ScheduleCreate
from app.enums import ScheduledStatus

def create_schedule(db: Session, schedule: ScheduleCreate):
    db_schedule = Schedule(**schedule.dict())
    db.add(db_schedule)
    db.commit()
    db.refresh(db_schedule)
    return db_schedule

def fetch_all_schedules(db: Session):
    db_schedule = db.query(Schedule)

    return db_schedule

def get_all_schedules(db: Session, skip:int = 0, limit=1000):
    return db.query(Schedule).offset(skip).limit(limit).all()