import pdb
from fastapi import  Request, APIRouter
from app import dependencies
from app.helpers.jobs import ssh_key_generation_job_scheduler, rule_run_scheduler
from sqlalchemy.orm import Session
from fastapi import  Depends

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
async def schedule_rule_run(request: Request,  db:Session = Depends(dependencies.get_db)):
    data = await request.json()
    start_date:str = data.get("start_date") # (Y-m-d)
    time:list = data.get("time")
    frequency:str = data.get("frequency")
    reference:str = data.get("reference")
    reference_id:int = data.get("reference_id")
    rule_run_scheduler(start_date, time, reference, reference_id,db, frequency)
    return {"result":"scheduled ssh regeneration job"}