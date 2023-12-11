from app.crud.schedule import create_schedule
from app.schemas.schedule import ScheduleCreate
from apscheduler.schedulers.background import BackgroundScheduler
import paramiko
from app.config import PRIVATE_KEY_FILE_NAME, PUBLIC_KEY_FILE_NAME, PRIVATE_KEY_FILE_PATH, PUBLIC_KEY_FILE_PATH, SSH_DIRECTORY
from app.crud.agent import get_agents_by_profile, get_rules_by_agent

from apscheduler.triggers.cron import CronTrigger
from app.helpers.ssh_helper import generate_ssh_key_pairs, connect_to_agent, copy_file_content_to_remote_server, search_file_extension_in_remote
from app.models.agent import Agent
from fastapi import  Depends
import shutil
from app.enums import References
from sqlalchemy.orm import Session
from app.models.schedule import Schedule
from datetime import datetime

import pdb

from app.models.rule import Rule


scheduler = BackgroundScheduler()
#TODO add it entry point
print("scheduler started")
scheduler.start()


def ssh_key_generation_job_scheduler(start_date:str, time:list, frequency=None):
    """
    Date strings are accepted in three different forms: date only (Y-m-d), date with time
    (Y-m-d H:M:S) or with date+time with microseconds (Y-m-d H:M:S.micro). Additionally you can
    override the time zone by giving a specific offset in the format specified by ISO 8601:
    Z (UTC), +HH:MM or -HH:MM.
    """
    
    print("scheduling ssh key regeneration job")
    trigger =  CronTrigger(second="*/15", start_date=start_date)
    # pdb.set_trace()
    if (frequency == "week"):
        trigger = CronTrigger(hour=time[0], minute=time[1], second=0, start_date=start_date, day_of_week=0)
    elif (frequency == "month"):
        trigger = CronTrigger(hour=time[0], minute=time[1], second=0, start_date=start_date, day=1)
        
    scheduler.add_job(ssh_key_generation_job, trigger)


def ssh_key_generation_job():
    print("generating ssh key....")
    # generate ssh key in server
    generate_ssh_key_pairs()
    
    # connect to all the agents and copy the new SSH public key of the server to the agents
    # db =  Depends(dependencies.get_db)
    is_agents_present = True
    limit = 10
    
    while(is_agents_present):
        # TODO please change the below line
        agents:list[Agent] = [{'name':"admin", "ip_address":"192.168.0.107"}]
        
        if(len(agents) <= limit):
            is_agents_present = False
        
        for agent in agents:
            user_name = agent['name']
            ip_address = agent['ip_address']
            ssh_connection = connect_to_agent(ip_address, user_name)
            sftp_client = ssh_connection.open_sftp()
            copy_file_content_to_remote_server(sftp_client, PUBLIC_KEY_FILE_NAME, "administrators_authorized_keys", "C:\ProgramData\ssh")
            ssh_connection.close()
            #test connection
            pkey = paramiko.RSAKey.from_private_key_file(PRIVATE_KEY_FILE_NAME)
            ssh_connection = connect_to_agent(ip_address, user_name, pkey)
            ssh_connection.close()
        
        print("replacing old ssh key with new ssh private key")   
        # replace server private key with the new key generated
        shutil.copyfile(PRIVATE_KEY_FILE_PATH, SSH_DIRECTORY+'/id_rsa_old')
        shutil.copyfile(PUBLIC_KEY_FILE_PATH, SSH_DIRECTORY+'/id_rsa_old.pub')
        shutil.copyfile(PRIVATE_KEY_FILE_NAME, PRIVATE_KEY_FILE_PATH)
        shutil.copyfile(PUBLIC_KEY_FILE_NAME, PUBLIC_KEY_FILE_PATH)


def rule_run_scheduler(schedule:Schedule, db:Session):
    print("scheduling rule run job")
    # Create a CronTrigger for every 10 seconds after 7:30 PM, starting today
    trigger = CronTrigger(minute="*/3", start_date="2023-12-10")

    if (schedule.frequency == "week"):
        trigger = CronTrigger(hour=schedule.hour, minute=schedule.minutes, second=0, start_date=schedule.start_date, day_of_week=0)
    elif (schedule.frequency == "month"):
        trigger = CronTrigger(hour=schedule.hour, minute=schedule.minutes, second=0, start_date=schedule.start_date, day=1)
    
    # fetch the reference and all the rules associated
    if (schedule.reference == References.AGENT.value):
        schedule_rules_for_agent(db, schedule.reference_id, trigger)
        print("scheduled rule run for the agent")
    elif (schedule.reference == References.AGENTPROFILE.value):
        # fetch all agents under the agentprofile
        # agents:list[Agent] = get_agents_by_profile(db, reference_id)
        # for agent in agents:
        #     schedule_rules_for_agent(db, agent.id, trigger)
        print("scheduled rule run for the agent profile")
    else:
        raise Exception("Unknown reference")


def schedule_rules_for_agent(db:Session, agent_id:int, trigger:CronTrigger):
    agent = get_rules_by_agent(db, agent_id)
    scheduler.add_job(search_file_extension_in_remote, trigger, [agent.ip_address, agent.name, "xlsx"])

    # for rule in agent.rules:
    #     #TODO add appropriate rule logic in code