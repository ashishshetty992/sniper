from pydantic import BaseSettings

class Settings(BaseSettings):
    SECRET_KEY: str = "ASHISH"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30  # Adjust the token expiration time as needed

settings = Settings()
