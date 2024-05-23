from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.exc import OperationalError
import os
import sys
from dotenv import load_dotenv
import time

from sqlalchemy.orm import sessionmaker

if getattr(sys, 'frozen', False):
    dir_path = sys._MEIPASS + '/setup.env'
else:
    dir_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__))) + "/setup/setup.env"

print(dir_path)
load_dotenv(dir_path)

MYSQL_USER_NAME = os.getenv('MYSQL_USER_NAME')
MYSQL_USER_PASSWORD = os.getenv('MYSQL_USER_PASSWORD')
MYSQL_DATABASE = os.getenv('MYSQL_DATABASE')
MYSQL_HOST = os.getenv('MYSQL_HOST', 'db')  # Default to 'db' for Docker Compose service name

DATABASE_URL = f"mysql+mysqlconnector://{MYSQL_USER_NAME}:{MYSQL_USER_PASSWORD}@{MYSQL_HOST}/{MYSQL_DATABASE}"

def connect_with_retry(database_url):
    retry_count = 0
    max_retries = 5
    while True:
        try:
            engine = create_engine(database_url)
            connection = engine.connect()
            # connection.execute("SELECT 1")  # Check if the connection is valid
            return engine
        except OperationalError as e:
            if retry_count >= max_retries:
                raise e
            retry_count += 1
            time.sleep(1)  # Wait for 1 second before retrying

# Usage
engine = connect_with_retry(DATABASE_URL)

print(f"--------------------{DATABASE_URL}-------------------------")

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
