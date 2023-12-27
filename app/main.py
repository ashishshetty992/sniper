from fastapi import Depends, FastAPI, HTTPException, dependencies
from app.routers import schedule, user, role, oauth, agentprofile, agent, rule
from app.database import engine, Base
from sqlalchemy.orm import Session

from app.crud.schedule import fetch_all_pending_schedules
from app.helpers.jobs import init_scheduler, rule_run_scheduler
from app.helpers.ssh_helper import generate_ssh_key_pairs
from app.dependencies import get_db
from sniper.app.config import PRIVATE_KEY_FILE_NAME, PUBLIC_KEY_FILE_NAME, SSH_DIRECTORY 

app = FastAPI()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os 

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
    try:
        print("scheduling all pending jobs")
        jobs = fetch_all_pending_schedules(db)
        for job in jobs:
            rule_run_scheduler(job,db)
    except Exception as e:
        print("Exception:", e)


def generate_ssh_keys_if_not_present():
    try:
        # check if ssh keys are present in the .ssh folder
        isdir = os.path.isdir(SSH_DIRECTORY+'/.ssh')
        isPublicFile = os.path.isfile(f"{SSH_DIRECTORY}/{PUBLIC_KEY_FILE_NAME}")
        isPrivateFile = os.path.isfile(f"{SSH_DIRECTORY}/{PRIVATE_KEY_FILE_NAME}")
        
        if (not isdir or not isPublicFile or not isPrivateFile):
            generate_ssh_key_pairs()
    except Exception as e:
        print("Exception:", e)


schedule_jobs()
generate_ssh_keys_if_not_present()