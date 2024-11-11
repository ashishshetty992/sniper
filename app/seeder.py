from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from app.database import Base, engine  # Import your database and engine setup
from app.models.agent import Agent
from app.models.agentprofile import AgentProfile

# Create a session
Session = sessionmaker(bind=engine)
session = Session()

# Seed data for Agent and AgentProfile
def seed_data():
    # Creating sample agents
    agents = [
        Agent(agent_name="Agent_001", name="Agent Smith", ip_address="192.168.1.1"),
        Agent(agent_name="Agent_002", name="Agent Johnson", ip_address="192.168.1.2"),
    ]

    # Creating sample agent profiles
    profiles = [
        AgentProfile(name="Profile Alpha", active=True),
        AgentProfile(name="Profile Beta", active=False),
    ]

    # Adding sample agents and profiles to session
    session.add_all(agents)
    session.add_all(profiles)
    session.commit()

    # Associating agents with profiles
    agents[0].profiles.append(profiles[0])  # Associate Agent_001 with Profile Alpha
    agents[1].profiles.append(profiles[1])  # Associate Agent_002 with Profile Beta

    # Commit associations
    session.commit()

    print("Data seeded successfully.")

# Run the seed function
if __name__ == "__main__":
    # Recreate tables (use only if you want to start fresh each time)
    # Base.metadata.drop_all(bind=engine)
    # Base.metadata.create_all(bind=engine)

    seed_data()