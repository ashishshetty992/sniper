from sqlalchemy import create_engine
# from sqlalchemy.ext.declarative import DeclarativeBase
from sqlalchemy.ext.declarative import declarative_base
import os
from dotenv import load_dotenv

from sqlalchemy.orm import sessionmaker

dir_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
load_dotenv(dir_path+"/setup/setup.env")

# DATABASE_URL = "mysql+mysqlconnector://sniper:password@192.168.0.100/sniper"
# DATABASE_URL = "mysql+mysqlconnector://shiksha:Shiksha123@172.31.5.1/sniper_new"
DATABASE_URL = f"mysql://{os.getenv("MYSQL_USER_NAME")}:{os.getenv("MYSQL_USER_PASSWORD")}@localhost/{os.getenv("MYSQL_DATABASE")}"
print("DATABASE_URL-->", DATABASE_URL)


engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base = DeclarativeBase()
Base = declarative_base()
