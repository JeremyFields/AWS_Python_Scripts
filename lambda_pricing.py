#!/usr/bin/python3
import boto3
from datetime import datetime, timedelta
import time
from pprint import pprint
import sys
'''#################################################################################
    
    This script takes in the log group name and the amount of hours to look back,
    queries CloudWatch Insights to retrieve data (request ID, billed duration),
    and returns the most expensive Lambda invocation via the "Billed duration" data.
    
    Args: log group, hour(s)

#################################################################################'''

client = boto3.client('logs')
lg = sys.argv[1]
time_delta = int(sys.argv[2])
log_group = f'/aws/lambda/{lg}'
query_string = 'filter @type = "REPORT" | fields @requestId, @billedDuration, @log | sort by @billedDuration desc | limit 5'
billed_duration_list = []
request_id_list = []
bill_to_id_list = []


def start_query(client, log_group, query):

    ''' This function schedules the cloudwatch insights query and returns the query ID'''

    # start query
    query_response = client.start_query(
        logGroupName = log_group,
        # how many hours back to query
        startTime = int((datetime.today() - timedelta(hours = time_delta)).timestamp()),
        endTime = int(datetime.now().timestamp()),
        queryString = query
    )
    return query_response

def get_query_results(client, query_id):

    ''' This function uses the query ID to locate and return the query results'''
    
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

def get_bill_and_id(client, response):
    
    ''' This function takes the query results and creates and returns a dictionary to correlate the Lambda 
    request ID to the billed duration, and two lists to hold the request ID's and billed duration times '''

    results = get_query_results(client, response['queryId'])
    if results['results']:
        for result in results['results']:
            if result[1]['field'] == '@billedDuration' and result[0]['field'] == '@requestId':
                billed_duration = result[1]['value']
                request_id = result[0]['value']
                bill_to_id = {billed_duration: request_id}
                bill_to_id_list.append(bill_to_id)
                billed_duration_list.append(result[1]['value'])
                request_id_list.append(result[0]['value'])
                  
        return billed_duration_list, request_id_list, bill_to_id_list
    
def calculate_time_and_id(billed_duration_list, bill_to_id_list):

    ''' This function takes the billed duration list and the request ID to billed duration correlated dict/list
        and calculates the highest (longest) billed duration and thus costliest invocation. Then loops
        through the correlated dict/list to find the correlated request ID to that highest billed duration'''

    high = billed_duration_list[0]
    for duration in billed_duration_list:
        if duration > high:
            high = duration
    
    for bill in bill_to_id_list:
        try:
            high_id = bill[high]
        except KeyError:
            pass
    pprint(f"Checking Lambda invocations within the last {time_delta} hour(s)...")
    time.sleep(2)
    pprint(f"Lambda with request ID: '{high_id}' is the most expensive lambda invocation with time: '{high}'")


def main():

    ''' main function '''

    query_response = start_query(client, log_group, query_string)
    get_bill_and_id(client, query_response)
    calculate_time_and_id(billed_duration_list, bill_to_id_list)

if __name__ == '__main__':
    main()
