#!/usr/bin/python3
### Author: Jeremy Fields ###
import boto3
from datetime import datetime, timedelta
import time
from pprint import pprint
import os

# create lists
query_list = []
request_id_list = []
client = boto3.client('logs')

# function to start the query: pass in boto3 client, log_group, query string
def start_query(client, log_group, query):
    # start query
    start_query_response = client.start_query(
        logGroupName = log_group,
        # set number of hours of logs to query
        startTime = int((datetime.today() - timedelta(hours = 168)).timestamp()),
        endTime = int(datetime.now().timestamp()),
        queryString = query,
    )
    return start_query_response

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

    log_group = '/aws/lambda/test-dap-transfer'

    '''---- Query and parse for [ERROR] ----'''
    # start_query will return a dictionary with the query ID - assign to error_query
    error_query = start_query(client, log_group, query_string_error)

    # get the output from get_query_results by passing the boto3 client and the query ID
    error_query_output = get_query_results(client, error_query['queryId'])

    # get the request ID of the error_query (this will be used to correlate the [ERROR] to it's [INFO])
    get_request_id(error_query_output)

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
        
        ## The request ID for the lambda invocation
        pprint(request_id)
        
        # object key
        pprint(info_object_key)
        
        # print the INFO list
        pprint(info_query_list)
        
# run main()
if __name__ == '__main__':
    main()