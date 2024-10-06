from sqlalchemy import create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.exc import OperationalError
import os
import sys
import time
from dotenv import load_dotenv
from sqlalchemy.orm import sessionmaker

# Load environment variables from .env file
if getattr(sys, 'frozen', False):
    dir_path = sys._MEIPASS + '/setup.env'
else:
    dir_path = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'setup/setup.env')

load_dotenv(dir_path)


# Get environment variables 
MYSQL_USER_NAME = os.getenv('MYSQL_USER_NAME')
MYSQL_USER_PASSWORD = os.getenv('MYSQL_USER_PASSWORD')
MYSQL_DATABASE = os.getenv('MYSQL_DATABASE')
MYSQL_HOST = os.getenv('MYSQL_HOST', 'db')  # Default to 'db' for Docker Compose service name

# Check if necessary environment variables are set
if not all([MYSQL_USER_NAME, MYSQL_USER_PASSWORD, MYSQL_DATABASE]):
    raise ValueError("Missing necessary environment variables: MYSQL_USER_NAME, MYSQL_USER_PASSWORD, or MYSQL_DATABASE")

# Create the database URL
DATABASE_URL = f"mysql+mysqlconnector://{MYSQL_USER_NAME}:{MYSQL_USER_PASSWORD}@{MYSQL_HOST}:3306/{MYSQL_DATABASE}"

print("DATABASE_URL===============================>", DATABASE_URL)

def connect_with_retry(database_url):
    retry_count = 0
    max_retries = 5

    while retry_count < max_retries:
        try:
            time.sleep(3)
            engine = create_engine(database_url)
            with engine.connect() as connection:
                # Use text() to make the SQL statement executable
                connection.execute(text("SELECT 1"))
            return engine
        except OperationalError as e:
            retry_count += 1
            print(f"Connection failed, retrying {retry_count}/{max_retries}...")
            time.sleep(1)  # Wait for 1 second before retrying

    raise Exception(f"Failed to connect to the database after {max_retries} attempts.")
# Usage

print("Connecting to the database...")
print("Connecting to the database...")
print("Connecting to the database...")
print("Connecting to the database... 4")
engine = connect_with_retry(DATABASE_URL)

print(f"--------------------{DATABASE_URL}-------------------------")

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()