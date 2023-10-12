from sqlalchemy.orm import Session
from passlib.context import CryptContext
from app.models.user import User
from app.models.role import Role
from app.schemas.user import UserCreate
from typing import List
import pdb

# Create a global CryptContext instance for password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class Crud:
    def create_user(db: Session, user_data: UserCreate, role_ids: List[int]):
        # Hash the user's password
        hashed_password = pwd_context.hash(user_data.password)

        # Convert UserCreate to a dictionary and add the hashed password
        user_dict = user_data.dict()
        user_dict["password"] = hashed_password

        db_user = User(**user_dict)

        # Assign roles to the user
        for role_id in role_ids:
            role = db.query(Role).filter(Role.id == role_id).first()
            if role:
                db_user.roles.append(role)

        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        return db_user
    
    def verify_password(plain_password, hashed_password):
        return pwd_context.verify(plain_password, hashed_password)

    def get_user(db: Session, username: str):
        return db.query(User).filter(User.username == username).first()

    def authenticate_user(db: Session, username: str, password: str):
        user = Crud.get_user(db, username)
        if user is None or not Crud.verify_password(password, user.password):
            return None
        return user