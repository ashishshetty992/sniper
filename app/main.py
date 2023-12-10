from fastapi import FastAPI
from app.routers import schedule, user, role, oauth, agentprofile, agent, rule
from app.database import engine, Base

app = FastAPI()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Define a list of allowed origins
# "*" means all origins are allowed. You can replace it with a specific origin like "http://localhost:8000" if needed.
origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Include routers
app.include_router(user.router)
app.include_router(role.router)
app.include_router(agent.router)
app.include_router(agentprofile.router)
app.include_router(rule.router)
app.include_router(oauth.router)
app.include_router(schedule.router)

# Create tables in the database
Base.metadata.create_all(bind=engine)
