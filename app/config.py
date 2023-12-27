import os


DATABASE_URL = "mysql+mysqlconnector://username:password@localhost/db_name"
PRIVATE_KEY_FILE_NAME = "new_ssh_private_key"
PUBLIC_KEY_FILE_NAME = "new_ssh_public_key"
SSH_DIRECTORY = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))),'.ssh')
PRIVATE_KEY_FILE_PATH = os.path.join(SSH_DIRECTORY, PRIVATE_KEY_FILE_NAME)
PUBLIC_KEY_FILE_PATH = os.path.join(SSH_DIRECTORY, PUBLIC_KEY_FILE_NAME)



