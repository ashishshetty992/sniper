from fastapi import Depends, FastAPI, dependencies
from app.routers import schedule, user, role, oauth, agentprofile, agent, rule
from app.database import engine, Base
from sqlalchemy.orm import Session

from app.crud.schedule import fetch_all_pending_schedules
from app.helpers.jobs import init_scheduler, rule_run_scheduler
from app.dependencies import get_db 

app = FastAPI()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Define a list of allowed origins
# "*" means all origins are allowed. You can replace it with a specific origin like "http://localhost:8000" if needed.
origins = ["*"]


app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Include routers
app.include_router(user.router)
app.include_router(role.router)
app.include_router(agent.router)
app.include_router(agentprofile.router)
app.include_router(rule.router)
app.include_router(oauth.router)
app.include_router(schedule.router)

# Create tables in the database
Base.metadata.create_all(bind=engine)

init_scheduler()

# fetch all scheduled jobs and run it if not executed
def schedule_jobs(db=next(get_db())):
    print("scheduling all pending jobs")
    jobs = fetch_all_pending_schedules(db)
    for job in jobs:
        rule_run_scheduler(job,db)

schedule_jobs()