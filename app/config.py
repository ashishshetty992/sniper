import os

DATABASE_URL = "mysql+mysqlconnector://sniper:password@db:3306/sniper"
PRIVATE_KEY_FILE_NAME = "new_ssh_private_key"
PUBLIC_KEY_FILE_NAME = "new_ssh_public_key"
SSH_DIRECTORY = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))),'setup')
PRIVATE_KEY_FILE_PATH = os.path.join(SSH_DIRECTORY, PRIVATE_KEY_FILE_NAME)
PUBLIC_KEY_FILE_PATH = os.path.join(SSH_DIRECTORY, PUBLIC_KEY_FILE_NAME)



