from io import StringIO
from apscheduler.schedulers.background import BackgroundScheduler
import paramiko
from app import dependencies
from app.config import PRIVATE_KEY_FILE_NAME, PUBLIC_KEY_FILE_NAME
from app.crud.agent import get_agents

from apscheduler.triggers.cron import CronTrigger
from app.helpers import ssh_helper
from app.models.agent import Agent
from fastapi import  Depends
import shutil
import pdb


scheduler = BackgroundScheduler()

def ssh_key_generation_job_scheduler(start_date:str, time:object, frequency=None):
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
        trigger = CronTrigger(hour=time.hour, minute=time.minute, second=0, start_date=start_date, day_of_week=0)
    elif (frequency == "month"):
        trigger = CronTrigger(hour=time.hour, minute=time.minute, second=0, start_date=start_date, day=1)
        
    scheduler.add_job(ssh_key_generation_job, trigger)


def ssh_key_generation_job():
    print("generating ssh key....")
    # generate ssh key in server
    ssh_helper.generate_ssh_key_pairs()
    
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
            ssh_connection = ssh_helper.connect_to_agent(ip_address, user_name)
            sftp_client = ssh_connection.open_sftp()
            ssh_helper.copy_file_content_to_remote_server(sftp_client, PUBLIC_KEY_FILE_NAME, "administrators_authorized_keys", "C:\ProgramData\ssh")
            ssh_connection.close()
            #test connection
            pkey = paramiko.RSAKey.from_private_key_file(PRIVATE_KEY_FILE_NAME)
            ssh_connection = ssh_helper.connect_to_agent(ip_address, user_name, pkey)
            ssh_connection.close()
        
        print("replacing old ssh key with new ssh private key")   
        # replace server private key with the new key generated
        shutil.copyfile("/users/lt/.ssh/id_rsa", "/users/lt/.ssh/id_rsa_old")
        shutil.copyfile("/users/lt/.ssh/id_rsa.pub", "/users/lt/.ssh/id_rsa_old.pub")
        shutil.copyfile(PRIVATE_KEY_FILE_NAME, "/users/lt/.ssh/id_rsa")
        shutil.copyfile(PUBLIC_KEY_FILE_NAME, "/users/lt/.ssh/id_rsa.pub")

#TODO add it entry point
scheduler.start()