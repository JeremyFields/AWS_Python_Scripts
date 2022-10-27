#!/usr/bin/python3
### Author: Jeremy Fields ###
''' Script to parse CloudWatch logs for s3-to-sftp errors,
    relate the error messages to the info messages,
    email the the s3 object key and errors to SFTP team '''
# ********************************************************************
# Module Imports

import sys
sys.path.append('/home/ec2-user/scripts/dev/aws_util')
from datetime import datetime, timedelta
from calendar import timegm
from pprint import pprint
import aws_assume
import json
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# *****************************************************************************
# Global Variables

# AWS
region = 'us-west-2'
lambda_name = sys.argv[1]
aws_account = str(sys.argv[2])
role = f"arn:aws:iam::{aws_account}:role/middleware-role"
log_group = f'/aws/lambda/{lambda_name}'
# Email
email_receiver = 'jeremy.fields@xxxx.com'
email_sender = 'noreply-sftpteam@xxxx.com'
email_append = '\nPlease contact the Choice Hotels SFTP team for support.\n\nSFTPTeam@xxxx.com'
# Time
now = datetime.utcnow()
start_time = now - timedelta(hours=1)
end_time = now
start_ms = timegm(start_time.utctimetuple()) * 1000
end_ms = timegm(end_time.utctimetuple()) * 1000
# Lists
error_list = []
ingestion_list = []
info_list = []

''' Config logger '''
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, filename='/home/ec2-user/scripts/dev/logs/lambda_logs_new.log', \
            filemode='a', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', \
            datefmt='%d-%b-%y %H:%M:%S')
            
''' JSON file to correlate acct numbers to friendly names '''
lambda_logs_json_config = '/home/ec2-user/scripts/dev/sftp_management/lambda_logs_dev.json'
jsonData = json.loads(open(lambda_logs_json_config).read())
aws_account_names = jsonData[aws_account]['friendlyname']

client = aws_assume.create_client("logs",
                                        region_name=region,
                                        assume_role_arn=role)

# *****************************************************************************
# Local Functions

def filter_logs():
    ''' Function to filter through error logs, capture 
        error message, and ingestionTime, filter through info,
        find info that correlates to that ingestion time. '''
    
    # 1st paginator to filter for errors
    error_paginator = client.get_paginator('filter_log_events')
    error_response_iterator = error_paginator.paginate(
        logGroupName=log_group,
        startTime=start_ms,
        endTime=end_ms,
        filterPattern="ERROR"
    )
    # loop through error events
    for response in error_response_iterator:
        if response['events']:
            for error_events in response['events']:
                # assign useful variables
                ingestion_time = error_events['ingestionTime']
                error_message = error_events['message']
                # create a list of error messages and ingestion times
                error_list.append(error_message)
                ingestion_list.append(ingestion_time)
            
    # 2nd paginator to filter for info
    info_paginator = client.get_paginator('filter_log_events')
    info_response_iterator = info_paginator.paginate(
        logGroupName=log_group,
        startTime = start_ms,
        endTime = end_ms,
        filterPattern="INFO"
    )
    # loop through info events
    for info in info_response_iterator:
        if info['events']:
            for info_events in info['events']:
                for ingestion_time in ingestion_list:
                    # find info messages that match error ingestion time
                    if info_events['ingestionTime'] == ingestion_time:
                        ### ---- pprint(info_events)
                        # find the key / path 
                        if "Key" in info_events['message']:
                            info_message = info_events['message']
                            # find info messages with the keys
                            info_list.append(info_message)
    return error_list, info_list
    

def email_team(error, info):
    ''' Method to email information to SFTP team '''
    error = ''.join(error)
    info = ''.join(info)
    mail_body = f"Errors found in: {lambda_name} in account: {aws_account_names} \
                \n\n{info}\n\n{error}\n\n{email_append}"
    msg = MIMEMultipart()
    msg['From'] = email_sender
    msg['To'] = email_receiver
    msg['Subject'] = 'SFTP Notification'
    msg.attach(MIMEText(mail_body, 'plain'))
    text = msg.as_string()
    server = smtplib.SMTP("localhost")
    server.sendmail(email_sender, email_receiver, text)
    print("Message sent successfully!")
    server.quit()

def main():
    error, info = filter_logs()
    # if errors, email team
    if error:
        email_team(error, info)
    else:
        # no errors, log @ /home/ec2-user/scripts/dev/logs/lambda_logs.log
        logger.info(f"There were no errors found in log group: '{lambda_name}' from account: '{aws_account_names}'")

if __name__ == '__main__':
    main()