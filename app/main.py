import pdb
from fastapi import Depends, FastAPI, HTTPException, dependencies
from app.routers import schedule, user, role, oauth, agentprofile, agent, rule, ruleexecutionresult
from app.database import engine, Base
from sqlalchemy.orm import Session

from app.crud.schedule import fetch_all_schedules
from app.helpers.jobs import init_scheduler, rule_run_scheduler
from app.helpers.ssh_helper import generate_ssh_key_pairs, main
from app.dependencies import get_db
from app.config import PRIVATE_KEY_FILE_NAME, PRIVATE_KEY_FILE_PATH, PUBLIC_KEY_FILE_NAME, PUBLIC_KEY_FILE_PATH, SSH_DIRECTORY
from app.enums import ScheduledStatus 
from datetime import datetime
from app.crud.role import get_roles
from app.crud.user import Crud
from app.seeder import seed_data

from app.schemas.user import UserCreate
from app.schemas.role import RoleCreate
from setup.setup import generate_ssh_keys_if_not_present

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
app.include_router(ruleexecutionresult.router)

def create_default_user_and_role(db=next(get_db())):
    try:
        #  check if user already exists
        user_data = Crud.get_user(db, "admin")
        if(user_data):
            return
        
        print("creating default admin user")
        # check if role exists
        role_data = get_roles(db)
        
        if (not role_data):
            print("creating role")
            default_role = RoleCreate.model_validate({"name":"admin"})
            role_data = role.create_role(default_role, db)
            role_ids = [role_data.id]
        else:
            print(" role already exists")
            role_ids = [i.id for i in role_data]
        
        default_user:UserCreate = {
            "username": "admin",
            "email": "admin@sniper.com",
            "full_name": "sniper admin",
            "is_superadmin": True,
            "disabled":False,
            "password":"sniper@123"
        }
        default_user = UserCreate.model_validate(default_user)
        user.create_default_user(default_user, role_ids, db)
    except Exception as e:
        print(e)
        print("failed to create user and role")

# Create tables in the database
Base.metadata.create_all(bind=engine)
print("SEEDING DATA")
# seed_data()

init_scheduler()

# fetch all scheduled jobs and run it if not executed
def schedule_jobs(db=next(get_db())):
    try:
        print("scheduling all pending jobs")
        jobs = fetch_all_schedules(db)
        for job in jobs:
            if (job.status != ScheduledStatus.EXECUTED.value):
                job.hour = datetime.now().hour
                job.minutes = datetime.now().minute + 1
            rule_run_scheduler(job,db)
    except Exception as e:
        print("Exception:", e)


# def generate_ssh_keys_if_not_present():
#     try:
#         # check if ssh keys are present in the .ssh folder
#         isdir = os.path.isdir(SSH_DIRECTORY)
#         isPublicFile = os.path.isfile(PUBLIC_KEY_FILE_PATH)
#         isPrivateFile = os.path.isfile(PRIVATE_KEY_FILE_PATH)
        
#         if (not isdir or not isPublicFile or not isPrivateFile):
#             generate_ssh_key_pairs()
#     except Exception as e:
#         print("Exception:", e)


create_default_user_and_role()
# generate_ssh_keys_if_not_present()
schedule_jobs()
generate_ssh_keys_if_not_present()