#!/usr/bin/python3
# Authored by: Jeremy Fields
# Script Name: update_ssh_pass_int.py
# Purpose: Updates internal SFTP user's public key in AWS Transfer Family
# Create Date: 8/24/2022
# Version: 1.0.0
# Version History: 1.0.0 - Creation
# 1.0.0, eremy Fields
# ********************************************************************
# Module Imports

import sys
sys.path.append('C:\\Users\\Jeremy.Fields\\Documents\\PythonScripts\\Working')
import argparse
import json
import logging
from pprint import pprint
from botocore.exceptions import ClientError
import boto3
import os

''' Create and config logger'''
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, filename='C:\\Users\\Jeremy.Fields\\Documents\\PythonScripts\\Logs\\int.log', \
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
sftp_json_config = 'C:\\Users\\Jeremy.Fields\\Documents\\PythonScripts\\JSON\\sftp_server_info.json'
jsonData = json.loads(open(sftp_json_config).read())

servername = jsonData['internal'][args.aws_account]['servername']
domain     = jsonData['internal'][args.aws_account]['domain']
serverId   = jsonData['internal'][args.aws_account]['serverId']
''' Create transfer family client '''
client = boto3.client("transfer")

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

def get_status_email_arn(user_list):
    ''' sets the status tag to ACTIVE
    '''
    try:
        for user in user_list:
            user_data = get_user_data(user)
            if user_data['User']['UserName'] == args.username:
                arn = user_data['User']['Arn']
                tag_list = user_data['User']['Tags']
                for tag in tag_list:
                    if tag['Key'] == 'status':
                        curr_status = tag['Value']
                    if tag['Key'] == 'email_address':
                        email = tag['Value']
        return curr_status, email, arn

    except Exception as e:
        logger.error(f"Error retrieving tags: {e}")

def update_tags(curr_status, arn):
    if curr_status == 'LOCKED':
        curr_status = 'ACTIVE'
        response = client.tag_resource(
            Arn=arn,
            Tags=[
                {
                    'Key': 'status',
                    'Value': curr_status
                }
            ]
        )
    
    return curr_status

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
                if user_data['User']['SshPublicKeys']:
                    for key in user_data['User']['SshPublicKeys']:
                        # if public key exists
                        if key['SshPublicKeyBody'] != args.ssh_key:
                            key_id = key['SshPublicKeyId']
                            pub_key = key['SshPublicKeyBody']
                            
                        else:
                            print("The passed key is the same as the current key")
                            sys.exit()
                else:
                    pub_key = False
                    key_id = False
                    logger.error(f"The user {args.username} does not have a public key")
            
                    
        return pub_key, key_id

    except Exception as e:
        logger.error(f"Error retrieving keys: {e}")
        raise e

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
        raise e

def email_team(server_id, key_id, username, status):
    ''' takes in the server ID, key ID, username, status
        Sends out email with that information to the SFTP team
    '''
    # Set email variables
    email_script = '/home/ec2-user/scripts/dev/common_code/mailsend.py'
    email_address = 'SFTPTeam@xxx.com'
    email_append = '\nPlease contact the Choice Hotels SFTP team for support.\n\nSFTPTeam@xxx.com'
    # email new pub key to SFTP team.
    email_body = (f"New SSH key for user: '{username}'\n\nSSH key: {args.ssh_key}\n\n \
        Key ID: {key_id}\n\nServer ID: {server_id}\n\nStatus: {status}")
    os.system(f"/bin/python3 {email_script} noreply-SFTPTeam@xxx.com {email_address} \
                '{username} - SSH key updated' '{email_body}\n{email_append}'")

def email_user(email_address):
    ''' takes in the email address and key
        Sends out email to the user with the information
    '''
    # Set email variables
    email_script = '/home/ec2-user/scripts/dev/common_code/mailsend.py'
    email_append = '\nPlease contact the Choice Hotels SFTP team for support.\n\nSFTPTeam@xxx.com'
    # email new pub key to user
    email_body = f"New SSH key for user: '{args.username}'\n\nSSH key: {args.ssh_key}"
    os.system(f"/bin/python3 {email_script} noreply-SFTPTeam@xxx.com {email_address} \
                '{args.username} - SSH key updated' '{email_body}\n{email_append}'")
    sys.exit()
        
# # *****************************************************************************
# main

def main():
    '''
    Gets the user list, retrieves current pub key & key ID,
    logs and removes the current pub key, imports the new pub key,
    sets status tag to ACTIVE, emails SFTP team with information.
    '''
    ''' add flag for replacing key or just adding key'''
    user_list = get_user_list()
    try:
        pub_key, key_id = get_key_info(user_list)
        curr_status, email_address, arn = get_status_email_arn(user_list)
        new_status = update_tags(curr_status, arn)
        if pub_key != False:
            remove_public_key(key_id, pub_key)
        set_key_response = set_public_key()
        email_team(set_key_response['ServerId'], set_key_response['SshPublicKeyId'],
                    set_key_response['UserName'], new_status)
        email_user(email_address)
    except Exception as e:
        logger.exception(f"Error occured: {e}")
        raise e

if __name__ == '__main__':
    main()