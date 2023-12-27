from sqlalchemy import create_engine
# from sqlalchemy.ext.declarative import DeclarativeBase
from sqlalchemy.ext.declarative import declarative_base

from sqlalchemy.orm import sessionmaker

# DATABASE_URL = "mysql+mysqlconnector://sniper:password@192.168.0.100/sniper"
# DATABASE_URL = "mysql+mysqlconnector://shiksha:Shiksha123@172.31.5.1/sniper_new"
DATABASE_URL = "mysql://avnadmin:AVNS_SLGLj-oA7Vkwm222SyW@sniper-ashishshetty992-5e41.a.aivencloud.com:14764/sniper_new"



engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base = DeclarativeBase()
Base = declarative_base()
