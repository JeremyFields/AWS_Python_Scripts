#!/usr/bin/python3
# Authored by: Jeremy Fields
# Script Name: update_ssh_pass_int.py
# Purpose: Updates internal SFTP user's public key in AWS Transfer Family
# Create Date: 8/24/2022
# Version: 1.0.0
# Version History: 1.0.0 - Creation
# 1.0.0, Jeremy Fields
# ********************************************************************
# Module Imports

import sys
sys.path.append('/home/ec2-user/scripts/dev/aws_util')
import argparse
import aws_assume
import json
import logging
from pprint import pprint
from botocore.exceptions import ClientError
import os

''' Create and config logger '''
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, filename='/home/ec2-user/scripts/dev/logs/update_ssh_pass_int.log', \
            filemode='a', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', \
            datefmt='%d-%b-%y %H:%M:%S')

# *****************************************************************************
# Global Variables
region   = "us-west-2"

''' Setting up argparse variables '''
parser = argparse.ArgumentParser()
parser.add_argument("ssh_key", action="store",
                     default='None', help="Examples: 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC'")
parser.add_argument("--aws_account", action="store",
                    default='None', help="Examples: 139438692016")
parser.add_argument("--username", action="store",
                    default='None', help="Examples: sftp-user-1")
args = parser.parse_args()

role = f"arn:aws:iam::{args.aws_account}:role/middleware-role"

''' Reading in JSON file '''
sftp_json_config = '/home/ec2-user/scripts/dev/sftp_management/users_to_db/sftp_server_info.json'
jsonData = json.loads(open(sftp_json_config).read())

servername = jsonData['internal'][args.aws_account]['servername']
domain     = jsonData['internal'][args.aws_account]['domain']
serverId   = jsonData['internal'][args.aws_account]['serverId']
''' Create transfer family client '''
client = aws_assume.create_client("transfer",
                                        region_name=region,
                                        assume_role_arn=role)

# *****************************************************************************
# Local Functions

def get_user_list():
    '''returns list of users
       from aws transfer family
    '''
    response = client.list_users(
        MaxResults=200,
        ServerId=serverId
    )
    user_list =   {i['UserName'] for i in response['Users']}

    return user_list

def get_user_data(user):
    ''' return user data 
        connect to AWS transfer family and return user data  
    '''
    response = client.describe_user(
    ServerId=serverId,
    UserName=user
    )

    return response

def set_status(user_list):
    ''' sets the status tag to ACTIVE
    '''
    try:
        for user in user_list:
            user_data = get_user_data(user)
            if user_data['User']['UserName'] == args.username:
                tag_list = user_data['User']['Tags']
                for tag in tag_list:
                    if tag['Key'] == 'status':
                        tag['Value'] == 'ACTIVE'
                        status = tag['Value']
        return status

    except Exception as e:
        logger.error(f"Error retrieving keys: {e}")

def get_key_info(user_list):
    ''' return user key 
        takes in a user list, parses for --username,
        and returns the pub key and key ID for that user
    '''
    try:
        for user in user_list:
            user_data = get_user_data(user)
            # find the --username user
            if user_data['User']['UserName'] == args.username:
                user = user_data['User']
                for key in user_data['User']['SshPublicKeys']:
                    # if public key exists
                    if key['SshPublicKeyBody']:
                        key_id = key['SshPublicKeyId']
                        pub_key = key['SshPublicKeyBody']
                        
                    else:
                        logger.error(f"The user {args.username} does not have a public key")
                    
        return pub_key, key_id

    except Exception as e:
        logger.error(f"Error retrieving keys: {e}")

def remove_public_key(key_id, pub_key):
    ''' takes in the key ID and public key
        and removes the current public key
    '''
    try:
        response = client.delete_ssh_public_key(
        ServerId=serverId,
        SshPublicKeyId=key_id,
        UserName=args.username
        )

        logger.info(f"Public key removed for user {args.username}. \
                    Old public key was: {pub_key}")
        return response

    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            logger.error(f"Error when removing public key: {e}")
            raise e
            
def set_public_key():
    ''' imports the new public key
    '''
    try:
            response = client.import_ssh_public_key(
            ServerId=serverId,
            SshPublicKeyBody=args.ssh_key,
            UserName=args.username
            )
            logger.info(f"New public key set for {args.username}. \
                        New public key is: {args.ssh_key}")
            return response

    except Exception as e:
        logger.error(f"Error when importing new public key {e}")

def email_team(server_id, key_id, username, status):
    ''' takes in the server ID, key ID, username, status
        Sends out email with that information to the SFTP team
    '''
    # Set email variables
    email_script = '/home/ec2-user/scripts/dev/common_code/mailsend.py'
    email_address = 'jeremy.fields@xxxx.com'
    email_append = '\nPlease contact the Choice Hotels SFTP team for support.\n\nSFTPTeam@xxxx.com'
    # if public key is passed to script, email new pub key.
    if args.ssh_key != 'None':
        email_body = f"New SSH key for user: '{username}'\n\nSSH key: {args.ssh_key}\n\nKey ID: {key_id}\n\nServer ID: {server_id}\n\nStatus: {status}"
        os.system(f"/bin/python3 {email_script} noreply-sftpteam@xxxx.com {email_address} \
                '{username} - SSH key updated' '{email_body}\n{email_append}'")
    sys.exit()
        
# # *****************************************************************************
# main

def main():
    '''
    Gets the user list, retrieves current pub key & key ID,
    logs and removes the current pub key, imports the new pub key,
    sets status tag to ACTIVE, emails SFTP team with information.
    '''
    user_list = get_user_list()
    pub_key, key_id = get_key_info(user_list)
    remove_public_key(key_id, pub_key)
    set_key_response = set_public_key()
    status = set_status(user_list)
    email_team(set_key_response['ServerId'], set_key_response['SshPublicKeyId'], \
                set_key_response['UserName'], status)

if __name__ == '__main__':
    main()
