from sqlalchemy import create_engine
# from sqlalchemy.ext.declarative import DeclarativeBase
from sqlalchemy.ext.declarative import declarative_base
import os
import sys
from dotenv import load_dotenv

from sqlalchemy.orm import sessionmaker

if getattr(sys, 'frozen', False):
    dir_path = sys._MEIPASS + '/setup.env'
else:
    dir_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))+"/setup/setup.env"

print(dir_path)
load_dotenv(dir_path)

# DATABASE_URL = "mysql+mysqlconnector://sniper:password@192.168.0.100/sniper"
# DATABASE_URL = "mysql+mysqlconnector://shiksha:Shiksha123@172.31.5.1/sniper_new"
DATABASE_URL = f"mysql://{os.getenv('MYSQL_USER_NAME')}:{os.getenv('MYSQL_USER_PASSWORD')}@localhost/{os.getenv('MYSQL_DATABASE')}"


engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base = DeclarativeBase()
Base = declarative_base()
