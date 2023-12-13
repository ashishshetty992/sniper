import pdb
from fastapi import  HTTPException, Request, APIRouter
from app import dependencies
from app.crud.schedule import create_schedule
from app.helpers.jobs import ssh_key_generation_job_scheduler, rule_run_scheduler
from sqlalchemy.orm import Session
from fastapi import  Depends

from app.schemas.schedule import ScheduleCreate

router = APIRouter()

@router.post("/schedule/ssh-key-regeneration")
async def schedule_ssh_key_regeneration(request: Request):
    data = await request.json()
    start_date:str = data.get("start_date") #(Y-m-d)
    time:list = data.get("time")
    frequency:str = data.get("frequency")
    ssh_key_generation_job_scheduler(start_date, time, frequency)
    return {"result":"scheduled ssh regeneration job"}


@router.post("/schedule/rule-run")
async def schedule_rule_run(schedule: ScheduleCreate,  db:Session = Depends(dependencies.get_db)):
    try:
        scheduler_item = create_schedule(db, schedule)
        rule_run_scheduler(scheduler_item, db)
        return {"result":"scheduled Rule run job"}
    except Exception as e:
        print("Exception:", e)
        raise HTTPException(status_code=400, detail="Failed to schedule rule")