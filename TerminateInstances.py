## Author: Jeremy Fields ##
import boto3
from botocore.exceptions import ClientError
from pprint import pprint
import sys

client = boto3.client('ec2')
# name of instance
passed_name = 'JeremyTest'         # sys.argv[1]
# dry run True | False
dry_run = False                    # sys.argv[2]


def get_instance_id(client, passed_name):
    '''
        Accepts the ec2 client and the instance name
        Returns the instance ID
    '''
    instances = client.describe_instances()

    for instance in instances['Reservations']:
        for data in instance['Instances']:
            for tag in data['Tags']:
                if tag['Key'] == 'Name':
                    if tag['Value'] == passed_name:
                        if data['State']['Name'] == 'running':
                            instance_id = data['InstanceId']
                        else:
                            instance_id = False
    
    return instance_id

def terminate_instances(client, instance_id, dry_run):
    '''
        Accepts the ec2 client, the instance ID and the dry run parameter
        Returns the response (termination successful or termination unsuccessful)
    '''
    response = client.terminate_instances(
        InstanceIds=[instance_id],
        DryRun=dry_run
    )

    return response

def main():
    '''
        Main method to run the functions
        Takes user input for verification prior to terminating instance
    '''
    try:
        instance_id = get_instance_id(client, passed_name)
        if instance_id == False:
            answer = False
        else:
            answer = input(f"Shutdown Instance: {passed_name} with Instance ID: {instance_id} (y/n)? ")
            answer = answer.lower()
    except UnboundLocalError as e:
        pass
    if answer == 'y' or answer == 'yes':
        try:
            term_response = terminate_instances(client, instance_id, dry_run)
            pprint(term_response)
        except ClientError as e:
            print("Unexpected error: %s" % e)
    elif answer == False:
        print("The instance / Instance ID does not exist.")
    else:
        print(f"Answered no, Instance: {passed_name} with Instance ID: {instance_id} will remain running.")

if __name__ == '__main__':
    main()

                





