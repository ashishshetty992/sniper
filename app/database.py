from sqlalchemy import create_engine
# from sqlalchemy.ext.declarative import DeclarativeBase
from sqlalchemy.ext.declarative import declarative_base

from sqlalchemy.orm import sessionmaker

DATABASE_URL = "mysql+mysqlconnector://sniper:password@192.168.0.107/sniper"



engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base = DeclarativeBase()
Base = declarative_base()
