#!/usr/bin/python3
### Author: Jeremy Fields ###
from site import execsitecustomize
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timedelta
import time
from pprint import pprint
import os
import sys

# create list for INFO
query_list = []
request_id_list = []
lambda_name = sys.argv[1]
aws_account = sys.argv[2]

def create_session(assume_role_arn=None):
    ''' Creates a session for clients and resources.

        Args:
            assume_role_arn: Optionally specify the ARN of a role to assume.

        Returns:
            A session to create clients and resources.
    '''

    if (assume_role_arn):
        sts_client = boto3.client('sts')
        assumed_role = sts_client.assume_role(RoleArn=assume_role_arn,
                                              RoleSessionName="AssumedRole")

        assumed_credentials = assumed_role['Credentials']

        session = boto3.Session(
            aws_access_key_id=assumed_credentials['AccessKeyId'],
            aws_secret_access_key=assumed_credentials['SecretAccessKey'],
            aws_session_token=assumed_credentials['SessionToken'])

    else:
        session = boto3.Session()

    return session

def create_client(service_name, region_name=None, assume_role_arn=None):
    ''' Creates a client for a service.

        Args:
            service_name: The name of the service client.
            region_name: Optionally the name of the region to use.
            assume_role_arn: Optionally the ARN of a role to assume.

        Returns:
            The client for the service.
    '''

    return create_session(assume_role_arn).client(service_name,
                                                  region_name=region_name)

# the role to assume
role = f'arn:aws:iam::{aws_account}:role/middleware-role'

# create CloudWatch Logs client, pass region, pass role to assume
client = create_client('logs', region_name='us-west-2', assume_role_arn=role)


# function to start the query: pass in boto3 client, log_group, query string
def start_query(client, log_group, query):
    # start query
    try:
        start_query_response = client.start_query(
            logGroupName = log_group,
            # set number of hours of logs to query
            startTime = int((datetime.today() - timedelta(hours = 1)).timestamp()),
            endTime = int(datetime.now().timestamp()),
            queryString = query,
        )
        return start_query_response
    except ClientError as e:
        return False

# function that returns the results of the query: pass in boto3 client, query ID
def get_query_results(client, query_id):
    # set to 'None' to enter the loop
    response = None

    # loop until query status is finished
    while response == None or response['status'] == 'Running':
        print("\nWaiting for query to complete ...\n")
        time.sleep(1)
        response = client.get_query_results(
            queryId = query_id
        )
    return response

# functions that accepts the query output and returns the request ID
def get_request_id(query_output):
    for item in query_output['results']:
        if item[2]['field'] == '@requestId':
            request_id_list.append(item[2]['value'])
       
    return request_id_list

# function to append the @message values into a list
def put_info_in_list(query_output):
    for item in query_output['results']:
        if item[0]['field'] == '@message':
            query_list.append(item[0]['value'])

    return query_list

# function to parse the INFO list and return the key (home/)
def get_object_key(query_info_list):
    for item in query_info_list:
        substring = "home/"
        index_of_key = item.find(substring)
        if index_of_key != -1:
            object_key = item.split(substring, 1)[1]
                
    return object_key
            
            
# main method
def main():
    ''' Set the initial query string and log group name'''
    query_string_error = 'fields @message, @timestamp, @requestId | filter @message like /ERROR/ |  limit 5'

    log_group = f'/aws/lambda/{lambda_name}'

    '''---- Query and parse for [ERROR] ----'''
    # start_query will return a dictionary with the query ID - assign to error_query
    error_query = start_query(client, log_group, query_string_error)
    if not error_query:
        print("Invalid Lambda name.")
        sys.exit()

    # get the output from get_query_results by passing the boto3 client and the query ID
    error_query_output = get_query_results(client, error_query['queryId'])

    # if no errors
    if not error_query_output['results']:
        print("No data to retrieve")
        sys.exit()

    # get the request ID of the error_query (this will be used to correlate the [ERROR] to it's [INFO])
    get_request_id(error_query_output)
    
    # set counter for tracking # of emails sent
    count = 1
    for request_id in request_id_list:
        
        '''---- Query and parse for [INFO] ----'''
        # set the query string to filter by INFO and filter by the request_id of original query
        info_query_string = "field @message, @timestamp, @requestId | filter @message like /INFO/ | filter @requestId like /" + request_id + "/ | limit 5"

        # start query to return dictionary with the query ID - assign to info_query
        info_query = start_query(client, log_group, info_query_string)

        # get the output from get_query_results by passing the boto3 client and the query ID
        info_query_output = get_query_results(client, info_query['queryId'])
        print("-"*66)
        print(f"Info retrieved for request ID {request_id}")
        print("-"*66)

        # put the INFO messages from the info_query into a list
        info_query_list = put_info_in_list(info_query_output)

        # parse object key from the INFO in the list
        info_object_key = get_object_key(info_query_list)
        info_object_key = info_object_key.split(" ", 1)[0]
        
        # try / except in the event no object key
        try:
            info_object_key = get_object_key(info_query_list)
            info_object_key = info_object_key.split(" ", 1)[0]
            if info_object_key:
                # write to file and email the file
                f = open('/tmp/output.txt','w')
                f.write(f"Error report for requestId {request_id}:\n\n" + str(info_query_list))
                f.close()
                os.system(f'mailx -s "{info_object_key} - Failed to transfer file" emails < /tmp/output.txt')
                os.system('rm /tmp/output.txt')
                print("-"*66)
                print(f"Error report email #{count} sent")
                print("-"*66)
                count += 1
        except:
            print("Info has no object key.")
        
# run main()
if __name__ == '__main__':
    main()