import subprocess
import os
from dotenv import load_dotenv

def install_mysql():
    try:
        subprocess.run(["mysql", "--version"], check=True)
        print("MySQL is already installed.")
    except Exception:
        print("Installing MySQL...")
        subprocess.run(["choco", "install", "mysql", "-y"], check=True)
        print("MySQL installed successfully.")

def configure_mysql():
    print("Configuring MySQL...")
    dir_path = os.path.dirname(os.path.realpath(__file__))
    print(dir_path)
    load_dotenv(dir_path+"/setup.env")
    # You can customize these variables according to your needs
    mysql_root_password = os.getenv('MYSQL_ROOT_PASSWORD') or "root_password"
    mysql_database = os.getenv("MYSQL_DATABASE") or "my_database"
    mysql_user = os.getenv("MYSQL_USER_NAME") or "mysql_user"
    mysql_user_password = os.getenv("MYSQL_USER_PASSWORD") or "mysql_password"

    print(mysql_root_password, mysql_database, mysql_user, mysql_user_password)
    # Set up MySQL root password
    subprocess.run(f'mysqladmin -u root password {mysql_root_password}', shell=True, check=True)

    # Create MySQL database and user
    subprocess.run(f'mysql -u root -p{mysql_root_password} -e "CREATE DATABASE {mysql_database}"', shell=True, check=True)
    subprocess.run(f'mysql -u root -p{mysql_root_password} -e "CREATE USER \'{mysql_user}\'@\'localhost\' IDENTIFIED BY \'{mysql_user_password}\'"', shell=True, check=True)
    subprocess.run(f'mysql -u root -p{mysql_root_password} -e "GRANT ALL PRIVILEGES ON {mysql_database}.* TO \'{mysql_user}\'@\'localhost\'"', shell=True, check=True)
    subprocess.run(f'mysql -u root -p{mysql_root_password} -e "FLUSH PRIVILEGES"', shell=True, check=True)

    print("MySQL configuration completed successfully.")

if __name__ == "__main__":
    install_mysql()
    configure_mysql()
