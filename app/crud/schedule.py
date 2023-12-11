from sqlalchemy.orm import Session
from app.models.schedule import Schedule
from app.schemas.schedule import ScheduleCreate

def create_schedule(db: Session, schedule: ScheduleCreate):
    db_schedule = Schedule(**schedule.dict())
    db.add(db_schedule)
    db.commit()
    db.refresh(db_schedule)
    return db_schedule