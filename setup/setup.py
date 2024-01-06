# script to setup initial resources and its run only once

import subprocess
import sys
import os

def set_env_variables():
    print("Setting up environment variables...")
    os.environ["MYSQL_ROOT_PASSWORD"] = input("Enter MySQL root password (default: root_password): ") or "root_password"
    os.environ["MYSQL_DATABASE"] = input("Enter MySQL database name (default: my_database): ") or "my_database"
    os.environ["MYSQL_USER"] = input("Enter MySQL user (default: mysql_user): ") or "mysql_user"
    os.environ["MYSQL_PASSWORD"] = input("Enter MySQL password (default: mysql_password): ") or "mysql_password"


def install_docker():
    try:
        subprocess.run(["docker", "--version"], check=True)
        print("Docker is already installed.")
    except subprocess.CalledProcessError:
        print("Installing Docker...")
        subprocess.run(["choco", "install", "docker-desktop", "-y"], check=True)
        print("Docker installed successfully.")

def run_docker_compose():
    print("Running Docker Compose...")
    subprocess.run(["docker-compose", "up", "-d"], check=True)
    print("Docker Compose completed successfully.")

if __name__ == "__main__":
    set_env_variables()
    
    if not os.path.exists("docker-compose.yml"):
        print("Error: docker-compose.yml not found. Please create the file.")
        sys.exit(1)

    install_docker()
    run_docker_compose()
