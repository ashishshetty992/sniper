from sqlalchemy.orm import Session
from app.models import role as role_models
from app.schemas import role as role_schemas
from typing import List

def create_role(db: Session, role: role_schemas.RoleCreate):
    db_role = role_models.Role(**role.dict())
    db.add(db_role)
    db.commit()
    db.refresh(db_role)
    return db_role

def get_role(db: Session, role_id: int):
    return db.query(role_models.Role).filter(role_models.Role.id == role_id).first()

def get_roles(db: Session, skip: int = 0, limit: int = 10):
    return db.query(role_models.Role).offset(skip).limit(limit).all()

def get_roles_by_ids(db: Session, role_ids: List[int]):
    return db.query(role_models.Role).filter(role_models.Role.id.in_(role_ids)).all()

# def update_role(db: Session, role_id: int, role: role_schemas.RoleUpdate):
#     db_role = db.query(role_models.Role).filter(role_models.Role.id == role_id).first()
#     if db_role:
#         for key, value in role.dict(exclude_unset=True).items():
#             setattr(db_role, key, value)
#         db.commit()
#         db.refresh(db_role)
#     return db_role

# def delete_role(db: Session, role_id: int):
#     db_role = db.query(role_models.Role).filter(role_models.Role.id == role_id).first()
#     if db_role:
#         db.delete(db_role)
#         db.commit()
 