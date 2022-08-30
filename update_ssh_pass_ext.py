#!/usr/bin/python3
# Authored by: Jeremy Fields
# Script Name: update_ssh_pass_ext.py
# Purpose: Updates secrets and exp. date with new PW/SSH Key
# Create Date: 8/4/2022
# Version: 1.0.0
# Version History: 1.0.0 - Creation
# 1.0.0, Jeremy Fields
# ********************************************************************
# Module Imports

import sys
sys.path.append('/home/ec2-user/scripts/dev/aws_util')
sys.path.append('/home/ec2-user/.local/lib/python3.7/site-packages')
import argparse
from datetime import datetime, timedelta
import aws_assume
import json
import base64
import logging
from pprint import pprint
from botocore.docs.docstring import PaginatorDocstring
from botocore.exceptions import ClientError
import os

''' Create and config logger '''
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, filename='/home/ec2-user/scripts/dev/logs/update_ssh_pass_ext.log', \
            filemode='a', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', \
            datefmt='%d-%b-%y %H:%M:%S')

# *****************************************************************************
# Global Variables
region   = "us-west-2"

''' Setting up argparse variables '''
parser = argparse.ArgumentParser()
parser.add_argument("--aws_account", action="store",
                    default='None', help="Examples: ??")
parser.add_argument("--username", action="store",
                    default='None', help="Examples: ??")
parser.add_argument("--password", action="store",
                    default='None', help="Examples: ??")
parser.add_argument("--ssh_key", action="store",
                    default='None', help="Examples: ??")
args = parser.parse_args()

role = f"arn:aws:iam::{args.aws_account}:role/middleware-role"

''' Reading in JSON file '''
sftp_json_config = '/home/ec2-user/scripts/dev/sftp_management/users_to_db/sftp_server_info.json'
jsonData = json.loads(open(sftp_json_config).read())

servername = jsonData['external'][args.aws_account]['servername']
domain     = jsonData['external'][args.aws_account]['domain']
serverid   = jsonData['external'][args.aws_account]['serverId']

secretsmanager_client = aws_assume.create_client("secretsmanager",
                                        region_name=region,
                                        assume_role_arn=role)

# *****************************************************************************
# Local Functions

def calc_exp_dates(user_data, secret_name):
    ''' if ssh key passed, add a year to exp time
        if pw passed, add 90 days to the exp time
    '''
    # set current date
    current_date = datetime.today().date()
    for user in user_data:
        if user['Name'] == secret_name:
            for item in user['Tags']:
                if item['Key'] == 'email_address':
                    user_email = item['Value']
                if item['Key'] == 'KeyExpirationDate':
                    if args.ssh_key != 'None':
                        new_exp_date = current_date + timedelta(days=365)
                    elif args.password != 'None':
                        new_exp_date = current_date + timedelta(days=90)
                if item['Key'] == 'status':
                    item['Value'] = 'ACTIVE'
                    status = item['Value']
    return str(new_exp_date), status, user_email

def get_home_directory(data):

    homedict = data['HomeDirectoryDetails']
    target_home = json.loads(homedict)
    
    for i in target_home:
        dir = i['Target']
        try:
            local_file_name = dir[dir.find('home'):]
        except Exception as e:
            print('missing home directory ', e)
        
    return local_file_name

def update_secrets(secret_values):
    ''' Updates the SSH key or the password '''
    secret_pwd_update = {'Password':f'{args.password}'}
    secret_key_update = {'PublicKey':f'{args.ssh_key}'}
    
    for key in secret_values:
        lower_key = key.lower()
        if lower_key == 'password':
        # if 'Password' in secret_values:
            logger.info(f"Password replaced in secrets, old password was: {secret_values['Password']}")
            secret_values.update(secret_pwd_update)
        if lower_key == 'publickey':
        # if 'PublicKey' in secret_values:
            logger.info(f"Public key replaced in secrets, old public key was: {secret_values['PublicKey']}")
            secret_values.update(secret_key_update)
        
    return secret_values

def get_secret(secret_name):
    
    try:
        response = secretsmanager_client.get_secret_value(SecretId=secret_name)
        if 'SecretString' in response:
            secret = response['SecretString']
        else:
            secret = base64.b64decode(response['SecretBinary'])
        return json.loads(secret)

    except Exception as e:
        logger.exception(f"Error with retrieving secrets: {e}")

def set_secret_values(secret_name, new_secrets):
    ''' Function that takes in the secret name and updated user dict
        and passed those values to update the secrets in AWS Secrets Manager '''
    try:
        secretsmanager_client.update_secret(SecretId=secret_name,
                            SecretString=json.dumps(new_secrets)
                            )
    except ClientError as e:
        if e.response['Error']['Code'] == 'InvalidRequestException':
            logger.exception(f"There was an error updating the secrets for {secret_name}")
            raise e
    
def get_all_users():
    all_user_lists = []
    paginator = secretsmanager_client.get_paginator('list_secrets')
    secrets_iterator = paginator.paginate() 
    
    for secrets in secrets_iterator:
        data = secrets['SecretList']
        for item in data:
            all_user_lists.append(item)
    
    return all_user_lists

def update_tags(secret_name, new_exp_date, status):
    response = secretsmanager_client.tag_resource(
        SecretId=secret_name,
        Tags=[
            {
            'Key': 'KeyExpirationDate',
            'Value': new_exp_date
            },
            {
            'Key': 'status',
            'Value': status
            }
        ]
    )
    
    return response

def email_team(email_address, server_id, status):
    ''' takes in the server ID, key ID, username, status
        Sends out email with that information to the SFTP team
    '''
    # Set email variables
    email_script = '/home/ec2-user/scripts/dev/common_code/mailsend.py'
    email_append = '\nPlease contact the SFTP team for support.\n\nxxx@gmail.com.com'
    # if public key is passed to script, email new pub key.
    if args.ssh_key != 'None':
        email_body = (f"New SSH key for user: '{args.username}'\n\nSSH key: {args.ssh_key}\n\n \
                        \n\nServer ID: {server_id}\n\nStatus: {status}")
        os.system(f"/bin/python3 {email_script} noreply-xxx@gmail.com.com {email_address} \
                '{args.username} - SSH key updated' '{email_body}\n{email_append}'")
    elif args.password != None:
        email_body = (f"New password for user: '{args.username}'\n\nPassword: {args.password}\n\n \
                        \n\nServer ID: {server_id}\n\nStatus: {status}")
        os.system(f"/bin/python3 {email_script} noreply-xxx@gmail.com.com {email_address} \
                '{args.username} - SSH key updated' '{email_body}\n{email_append}'")

def email_user(user_email):
    ''' takes in the email address and key
        Sends out email to the user with the information
    '''
    # Set email variables
    email_script = '/home/ec2-user/scripts/dev/common_code/mailsend.py'
    email_append = '\nPlease contact the SFTP team for support.\n\nxxx@gmail.com.com'
    # email new pub key to user
    if args.ssh_key != 'None':
        email_body = f"New SSH key for user: '{args.username}'\n\nSSH key: {args.ssh_key}"
        os.system(f"/bin/python3 {email_script} noreply-xxx@gmail.com.com {user_email} \
                '{args.username} - SSH key updated' '{email_body}\n{email_append}'")
    elif args.password != None:
        email_body = f"New password for user: '{args.username}'\n\nPassword: {args.password}"
        os.system(f"/bin/python3 {email_script} noreply-xxx@gmail.com.com {user_email} \
                '{args.username} - SSH key updated' '{email_body}\n{email_append}'")
    sys.exit()
        
        
# *****************************************************************************
# main

def main():
    # jeremy_test_user
    email_address = 'SFTPTeam@gmail.com'
    secret_name = f"SFTP/{args.username}"
    secret_values = get_secret(secret_name)
    new_secrets = update_secrets(secret_values)
    set_secret_values(secret_name, new_secrets)
    user_data = get_all_users()
    new_exp_date, status, user_email = calc_exp_dates(user_data, secret_name)
    update_tags(secret_name, new_exp_date, status)
    email_team(email_address, serverid, status)
    email_user(user_email)

if __name__ == '__main__':
    main()
