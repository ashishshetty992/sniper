from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import engine, Base, SessionLocal
from app import crud, models, security, schemas
from app.schemas import User
from app.routers import admin, user, agent, rule, profile  # Import your router modules
from app.config import settings
from app.security import get_current_user

app = FastAPI()

# Initialize the database tables
Base.metadata.create_all(bind=engine)

# Function to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Include your router modules
app.include_router(admin.router, prefix="/admins", tags=["Admins"])
app.include_router(user.router, prefix="/users", tags=["Users"])
# app.include_router(agent.router, prefix="/agents", tags=["Agents"])
# app.include_router(rule.router, prefix="/rules", tags=["Rules"])
# app.include_router(profile.router, prefix="/profiles", tags=["Profiles"])

# Route to get the current user's profile
@app.get("/user/", response_model=User)
def read_user_profile(current_user: models.User = Depends(security.get_current_user), db: Session = Depends(get_db)):
    profile = crud.get_user_profile(db, current_user.id)
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found")
    return profile

# Add more routes and security checks as needed

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
