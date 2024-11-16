""" script to connect to the remote agents
"""
import os
import sys
import paramiko
import stat
import pdb
import json

from app.config import PRIVATE_KEY_FILE_NAME, PRIVATE_KEY_FILE_PATH, PUBLIC_KEY_FILE_NAME, PUBLIC_KEY_FILE_PATH, SSH_DIRECTORY


def make_ssh_connection(hostname,username, password=None, port=22):
    """Method to make ssh connection to remote agents and add ssh key to remote server

    :param hostname: host name or ip of the remote agent
    :type hostname: str
    :param username: remote agnet user name
    :type username: str
    :param password: user password
    :type password: str
    :param port: ssh port, defaults to 22
    :type port: int, optional
    """
    try:
        print("Establishing SSH connection")
        ssh_client = paramiko.SSHClient()
        
        #password authentication 
        connect_to_agent(hostname=hostname,port=port,username=username,password=password, ssh_client=ssh_client)
        
        sftp_client = ssh_client.open_sftp()
        
        #copy public key to remote server
        copy_file_content_to_remote_server(sftp_client, PUBLIC_KEY_FILE_PATH, "administrators_authorized_keys", "C:\ProgramData\ssh", 'w')
        
        #command to give certain permission and restriction for authorized keys
        #TO DO fetch the path without hardoding
        dir_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))+"/scripts/setPermissionToAdminAuthKey.ps1"
        set_permissions_to_remote_ssh_key(sftp_client, ssh_client, dir_path, "setPermissionToAdminAuthKey.ps1")
        sftp_client.chdir(None)
        copy_file_content_to_remote_server(sftp_client, PUBLIC_KEY_FILE_PATH, "authorized_keys", f"C:\\Users\\{username}\\.ssh", 'w')
        set_permissions_to_remote_ssh_key(sftp_client, ssh_client, dir_path, "setPermissionToAdminAuthKey.ps1")
        
        #close connection using password authentication
        ssh_client.close()
        
        # test connection with key based authentication
        connect_to_agent(hostname=hostname,port=port,username=username, ssh_client=ssh_client)
        return True
    except Exception as e:
        print("Error: ", e)
        raise Exception("Failed to make SSH Connection")
    finally:
        ssh_client.close()


def connect_to_agent(hostname,username, password=None, port=22, pkey=None, ssh_client=None, timeout=10):
    """Connect to SSH server and authenticate ither using passowrd or key based

    :param hostname: host name or ip of the remote agent
    :type hostname: str
    :param username: remote agnet user name
    :type username: str
    :param password: user password
    :type password: str
    :param port: ssh port, defaults to 22
    :type port: int, optional
    :param pkey: private key object, defaults to None
    :type pkey: .object, optional
    
    """
    try:
        if (not ssh_client):
            ssh_client = paramiko.SSHClient()
        if (not pkey):
            pkey = paramiko.RSAKey.from_private_key_file(PRIVATE_KEY_FILE_PATH)
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if password:
            print(f"authenticating using passowrd")
            ssh_client.connect(hostname=hostname,port=port,username=username,password=password,timeout=timeout)
        elif pkey:
            print(f"authenticating using key based")
            ssh_client.connect(hostname=hostname,port=port,username=username,pkey=pkey,timeout=timeout)
        else:
            raise Exception("password or Private key object is expected for making ssh connection")

        print(f"Succefully connected to {hostname}")
        return ssh_client
    except Exception as e :
        raise Exception(f"Failed to connect to remote server {hostname} with Error : {e}")


def copy_file_to_server(sftp_client, local_file_path, remote_file_path, directory=None):
    """Copy file from local to remote server

    :param sftp_client: SFTP client
    :type sftp_client: object
    :param local_file_path: path including file name to be copes
    :type local_file_path: str
    :param remote_file_path: remote location oath where the file needs to be copied
    :type remote_file_path: str
    :param directory: In case different file name needs to be created other than the local file name set the diretory path, defaults to None
    :type directory: str, optional
    """
    try:
        print(f"copying {local_file_path} to {remote_file_path}")
        if(directory):
            sftp_client.chdir(directory)
        if(not local_file_path or not remote_file_path):
            raise Exception("Please ensure both local_file_path and remote_file_path is provided")
        sftp_client.put(local_file_path, remote_file_path)
        
        print(f"Succesfully copied {local_file_path} to {remote_file_path}")
    except Exception as e:
        raise Exception(f"Failed to copy file to server with error : {e}")


def copy_file_content_to_remote_server(sftp_client, local_file_path, remote_file_name, directory=None, mode='a'):
    """Copy file content from local to remote server

    :param sftp_client: SFTP client
    :type sftp_client: object
    :param local_file_path: path including file name to be copes
    :type local_file_path: str
    :param remote_file_path: remote location oath where the file needs to be copied
    :type remote_file_path: str
    :param directory: In case different file name needs to be created other than the local file name set the diretory path, defaults to None
    :type directory: str, optional
    """
    try:
        print(f"copying {local_file_path} to {remote_file_name}")
        if(directory):
            print("directory: ", directory)
            try:
                sftp_client.chdir(directory)
            except IOError:
                sftp_client.mkdir(directory)  # Create remote_path
                sftp_client.chdir(directory)
        if(not local_file_path or not remote_file_name):
            raise Exception("Please ensure both local_file_path and remote_file_path is provided")
        
        with sftp_client.file(remote_file_name, mode) as remote_file:
                print("inside")
                # Read the content of the local file
                with open(local_file_path, 'r') as local_file:
                    content = local_file.read()
                remote_file.write('\n' + content)
        print(f"Content from {local_file_path} appended to {remote_file_name}")
        # sftp_client.chdir(None)
    except Exception as e:
        raise Exception(f"Failed to copy file to server with error : {e}")


def set_permissions_to_remote_ssh_key(sftp_client, ssh_client, source_path, destination_path):
    """sets necessary permission and restriction to ssh publick key copied to the remote server

    :param sftp_client: SFTP client
    :type sftp_client: object
    :param permission_script_path: local script path
    :type permission_script_path: str
    :param destination_file: remote destination path
    :type destination_file: str
    """
    try:
        print("setting neccessary permission to the ssh key")
        current_directory = sftp_client.getcwd()
        if current_directory.startswith('/'):
            current_directory = current_directory[1:]
        copy_file_to_server(sftp_client, source_path, destination_path)
        destination_script_path = current_directory+f"/{destination_path}"
        ps_command = f'Powershell.exe -ExecutionPolicy Bypass -File "{destination_script_path}"'
        stdin, stdout, stderr = ssh_client.exec_command(ps_command)
        
        
        if(stderr.read().decode() and stderr.read().decode()!=""):
            raise Exception(stderr.read().decode())
        
        # Print the output and errors
        print("Output:", stdout.read().decode())
        
        # remove the script from server once the permission is set
        sftp_client.remove(destination_path)
    except Exception as e:
        raise Exception(f"Failed to set permission to ssh key with error :{e}")


def generate_ssh_key_pairs():
    key = paramiko.RSAKey.generate(2048)
    # key.from_private_key(keyout)
    os.makedirs(SSH_DIRECTORY, exist_ok=True)
    key.write_private_key_file(PRIVATE_KEY_FILE_PATH)
    public_key = '{} {}'.format(key.get_name(), key.get_base64())
    file = open(PUBLIC_KEY_FILE_PATH)
    file.write(public_key)
    file.close()


def execute_rule_in_remote(hostname, username, rule_file, remote_path="C:"):
    print(hostname, username, rule_file, remote_path)
    ssh_client = connect_to_agent(hostname, username)

    print(f"Running rule for the agent")

    # copy the rule in agent
    sftp_client = ssh_client.open_sftp()
    filename = os.path.basename(rule_file)

    # First, copy test_yara_agent.py to the remote machine
    agent_script = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "test_yara_agent.py")
    copy_file_content_to_remote_server(sftp_client, agent_script, "test_yara_agent.py", "C:\ProgramData\\rules", "w")
    
    # Then copy the rule file
    copy_file_content_to_remote_server(sftp_client, rule_file, filename, "C:\ProgramData\\rules", "w")

    rule_path = f"C:\ProgramData\\rules\\{filename}"
    agent_path = "C:\ProgramData\\rules\\test_yara_agent.py"
    print("remote_path--->", remote_path)
    
    # Run the Python script
    print(f"Executing command: python3 \"{agent_path}\" \"{rule_path}\" \"{remote_path}\"")
    stdin, stdout, stderr = ssh_client.exec_command(f"python3 \"{agent_path}\" \"{rule_path}\" \"{remote_path}\"")
    error = stderr.read().decode() 

    if error and error != "":
        print("error", error)
        raise Exception(error)
    
    # Process JSON results
    results = []
    for line in stdout:
        try:
            result = json.loads(line.strip())
            results.append(result)
        except json.JSONDecodeError as e:
            print(f"Warning: Could not parse line as JSON: {line}")
            continue

    print("Output:", results)
    return results


def main(host_name, user_name, password):
    """Driver function to make connection with remote agents
    """
    # print("arguments are: ", sys.argv)
    # for i in range(1, len(sys.argv)):
    # host_name, user_name, password = sys.argv[i].split(',')
    
    if(not host_name or not user_name or not password):
        print(f"""Invalid inputs in {i} position. Ensure that host_name,user_name,password is given correctly.
        EX: python script.py '192.168.0.105','admin','admin123'""")

    make_ssh_connection(host_name, user_name, password)