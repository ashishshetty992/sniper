from app.crud.schedule import create_schedule
from app.schemas.schedule import ScheduleCreate
from apscheduler.schedulers.background import BackgroundScheduler
import paramiko
from app.config import PRIVATE_KEY_FILE_NAME, PUBLIC_KEY_FILE_NAME, PRIVATE_KEY_FILE_PATH, PUBLIC_KEY_FILE_PATH, SSH_DIRECTORY
from app.crud.agent import get_agent, get_agents_by_profile, get_rules_by_agent

from apscheduler.triggers.cron import CronTrigger
from app.helpers.ssh_helper import generate_ssh_key_pairs, connect_to_agent, copy_file_content_to_remote_server, execute_rule_in_remote
from app.models.agent import Agent
from fastapi import  Depends
import shutil
from app.enums import References, ScheduledStatus
from sqlalchemy.orm import Session
from app.models.schedule import Schedule
from datetime import datetime

import pdb
import re

from app.models.rule import Rule
from app.crud.agentprofile import get_agent_profile
from app.crud.rule import get_all_agents_and_rule_by_rule_id, get_rule
from app.models.rule_execution_result import RuleExecutionResult
from app import dependencies
from app.database import SessionLocal


scheduler = BackgroundScheduler()

def init_scheduler():
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
        shutil.copyfile(PRIVATE_KEY_FILE_NAME, PRIVATE_KEY_FILE_PATH)
        shutil.copyfile(PUBLIC_KEY_FILE_NAME, PUBLIC_KEY_FILE_PATH)


def rule_run_scheduler(schedule:Schedule, db:Session):
    print("scheduling rule run job")

    trigger = CronTrigger(hour=schedule.hour, minute=schedule.minutes, start_date=schedule.start_date)

    if (schedule.frequency == "week"):
        trigger = CronTrigger(hour=schedule.hour, minute=schedule.minutes, second=0, start_date=schedule.start_date, day_of_week=0)
    elif (schedule.frequency == "month"):
        trigger = CronTrigger(hour=schedule.hour, minute=schedule.minutes, second=0, start_date=schedule.start_date, day=1)
    
    # fetch the reference and all the rules associated
    print(f"fetching rules and agents for reference_id : {schedule.reference_id}, reference: {schedule.reference}")
    [agents, rules] = get_agents_and_rules_reference_id(db, schedule.reference, schedule.reference_id)
    print(f"fetched rules and agentsfor reference_id : {schedule.reference_id}, reference: {schedule.reference}, agent:{agents}")
    for agent in agents:
        schedule_rules_for_agent(db, agent.id, rules, trigger, schedule.id)


def get_agents_and_rules_reference_id(db:Session, reference:str, reference_id:int):
    if (reference == References.AGENT.value):
        agent = get_rules_by_agent(db, reference_id)
        rules = agent.rules
        agents = [agent]
    elif (reference == References.AGENTPROFILE.value):
        agent_profile = get_agent_profile(db, reference_id)
        agents = agent_profile.agents
        rules = agent_profile.rules
    elif (reference == References.RULE.value):
        [agents, rule] = get_all_agents_and_rule_by_rule_id(db, reference_id)
        rules = [rule]
    else:
        raise Exception("unknown reference")
    return [agents, rules]


def schedule_rules_for_agent(db:Session, agent_id:int, rules:list[Rule], trigger:CronTrigger, schedule_id:int):
    dbschedule = db.query(Schedule).filter(Schedule.id == schedule_id).first()
    dbschedule.status = ScheduledStatus.SCHEDULED.value
    db.add(dbschedule)
    for rule in rules:
        print(f"scheduling rule for agent {agent_id} and rule : {rule.id}")
        scheduler.add_job(rule_execution_job, trigger, [agent_id, rule.id, schedule_id])
    db.commit()

def rule_execution_job(agent_id:int, rule_id:int, schedule_id:int):
    db = SessionLocal()
    db_result = None
    agent = get_agent(db, agent_id)
    rule = get_rule(db, rule_id)
    print(f"running rule for agent id : {agent.id} rule: {rule.id}")
    dbschedule = db.query(Schedule).filter(Schedule.id == schedule_id).first()
    dbschedule.status = ScheduledStatus.RUNNING.value
    db.add(dbschedule)
    db.expire_on_commit=False
    db.commit()
    try:
        rule_files = rule.exec_rule.split(',')
        print("rule_files--->",rule_files)
        for file in rule_files:
            start_time = datetime.now().timestamp()
            result = []
            try:
                result = execute_rule_in_remote(agent.ip_address, agent.name, file, rule.path)
                print("running rule on agent")
                print("result from agent with yara_scan--->", result)
            except Exception as e:
                db_result = RuleExecutionResult(details=str(e), agent=[agent], rule=[rule], schedule=[dbschedule], status='failed')
                db.add(db_result)
                db.commit()
                db.refresh(db_result)
            end_time = datetime.now().timestamp()
            latency = end_time - start_time
            if isinstance(result, dict) and result["status"] in ["success", "partial_success"]:
                for match in result.get("matches", []):
                    details = json.dumps(match)
                    file_name = file
                    rule_name = os.path.basename(file)  # Use the rule file name
                    severity = "low"  # You might want to extract this from match data
                    scanned_file = match["file"]
                    print("saving execution results in db")
                    db_result = RuleExecutionResult(
                        details=details,
                        latency=latency,
                        status='success',
                        file_name=file_name,
                        rule_name=rule_name,
                        severity=severity,
                        scanned_file=scanned_file
                    )
                    db_result.agent.append(agent)
                    db_result.rule.append(rule)
                    db_result.schedule.append(dbschedule)
                    db.add(db_result)
                    db.commit()
                    db.refresh(db_result)
            dbschedule = db.query(Schedule).filter(Schedule.id == dbschedule.id).first()
            dbschedule.status = ScheduledStatus.EXECUTED.value
            db.add(dbschedule)
            db.commit()
    except Exception as e:
        db_result = RuleExecutionResult(details=str(e), agent=[agent], rule=[rule], schedule=[dbschedule], status='failed')
        db.add(db_result)
        db.commit()
        db.refresh(db_result)
    db.expunge(dbschedule)
    return db_result


def parse_result(data):
    # Using regular expression to split the string
    match =re.match(r'(\S+)\s+\[.*?severity="(\w+)"\]\s+(.*)', data)
    if match:
        part1 = match.group(1)
        part2 = match.group(2)
        part3 = match.group(3)
    else:
        part1 = ""
        part2 = ""
        part3 = ""

    return [part1, part2, part3]
