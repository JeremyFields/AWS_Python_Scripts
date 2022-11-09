#!/usr/bin/python3
# Authored by: Jeremy Fields
# Script Name: update_pub_key_int.py
# Purpose: Updates internal SFTP user's public key in AWS Transfer Family
# Create Date: 11/9/2022
# Version: 2.0.0

# *********************** CHANGE LOG ***************************************
# 8/24/22 - V.1 - Replaces first pub key with new key
# 11/9/22 - V.2 - Added ability to handle multiple keys
#   - Optional Args: --pub_key (add new public key), --aws_account,
#                    --username (SFTP user), -r --remove (remove oldest key)
#               
# **************************************************************************
# Module Imports

import sys
sys.path.append('/home/ec2-user/scripts/dev/aws_util')
sys.path.append('/home/ec2-user/.local/lib/python3.7/site-packages')
import argparse
import aws_assume
import json
import logging
from pprint import pprint
from botocore.exceptions import ClientError
import os

''' Create and config logger'''
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, filename='/home/ec2-user/scripts/dev/logs/update_ssh_pass_int_DEV.log', \
            filemode='a', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', \
            datefmt='%d-%b-%y %H:%M:%S')

# *****************************************************************************
# Global Variables
region   = "us-west-2"

''' Setting up argparse variables '''
parser = argparse.ArgumentParser()
parser.add_argument("--pub_key", action="store",
                    help="Examples: 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC'")
parser.add_argument("--aws_account", action="store",
                    default='None', help="Examples: 139438692016")
parser.add_argument("--username", action="store",
                    default='None', help="Examples: sftp-user-1")
parser.add_argument("-r", "--remove", action="store_true",
                    help="remove current key")
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

def get_public_keys():
    ''' returns the public keys of the user '''
    response = client.describe_user(
        ServerId=serverId,
        UserName=args.username
    )

    return response['User']['SshPublicKeys']

def get_arn():
    ''' returns the ARN of the user '''
    response = client.describe_user(
        ServerId=serverId,
        UserName=args.username
    )

    return response['User']['Arn']

def get_tags():
    ''' returns the email address of the user '''
    response = client.describe_user(
        ServerId=serverId,
        UserName=args.username
    )
    
    for tag in response['User']['Tags']:
        if tag['Key'] == 'email_address':
            user_email_address = tag['Value']
        if tag['Key'] == 'status':
            status = tag['Value']

    return status, user_email_address


def set_public_key():
    ''' imports the new public key '''
    try:
            response = client.import_ssh_public_key(
                ServerId=serverId,
                SshPublicKeyBody= args.pub_key,
                UserName=args.username
            )
            logger.info(f"New public key set for {args.username}. \
                        New public key is: {args.pub_key}")
            return response

    except Exception as e:
        if e.response['Error']['Code'] == 'ResourceExistsException':
            logger.error(f"Public key already exists!")
            raise e

def remove_oldest_key(public_keys):
    ''' Removes the oldest key '''
    dates = []
    for key in public_keys:
        dates.append(key['DateImported'])
    for key in public_keys:
        if key['DateImported'] == min(dates):
            key_id = key['SshPublicKeyId']
            pub_key = key['SshPublicKeyBody']

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

def update_status(arn):
    ''' If acct is locked, set to ACTIVE '''
    response = client.describe_user(
        ServerId=serverId,
        UserName=args.username
    )
    for tag in response['User']['Tags']:
       if tag['Key'] == 'status':
        if tag['Value'] == 'LOCKED':
            response = client.tag_resource(
                Arn=arn,
                Tags=[
                    {
                    'Key': 'status',
                    'Value': 'ACTIVE'
                    }
                ]
            )
    
def email_team(status):
    ''' takes in the status of the user, sends 
        email with information to the SFTP team '''
    # email variables
    email_script = '/home/ec2-user/scripts/dev/common_code/mailsend.py'
    email_address = 'SFTPTeam@xxxx.com'
    email_append = '\nPlease contact the SFTP team for support.\n\nSFTPTeam@xxxx.com'
    # email new pub key to SFTP team.
    email_body = (f"New public key for user: '{args.username}'\n\nPublic key: {args.pub_key} \
        \n\nServer: {servername}\n\nDomain: {domain}\n\nStatus: {status}")
    os.system(f"/bin/python3 {email_script} noreply-sftpteam@xxxx.com {email_address} \
                '{args.username} - SSH key updated' '{email_body}\n{email_append}'")

def email_user(email_address):
    ''' takes in the email address and sends out
        email to the user with the information '''
    # email variables
    email_script = '/home/ec2-user/scripts/dev/common_code/mailsend.py'
    email_append = '\nPlease contact the SFTP team for support.\n\nSFTPTeam@xxxx.com'
    # email new pub key to user
    email_body = f"New public key for user: '{args.username}'\n\nPublic key: {args.pub_key}"
    os.system(f"/bin/python3 {email_script} noreply-sftpteam@xxxx.com {email_address} \
                '{args.username} - SSH key updated' '{email_body}\n{email_append}'")

# # # *****************************************************************************
# Main

def main():
    current_public_keys = get_public_keys()
    status, user_email_address = get_tags()
    user_arn = get_arn()
    if args.pub_key:
        set_key_response = set_public_key()
        update_status(user_arn)
        email_team(status)
        email_user(user_email_address)
    if args.remove:
        remove_oldest_key(current_public_keys)
    
if __name__ == '__main__':
    main()
    


        

