#!/usr/bin/python3
import boto3
from pprint import pprint

# create autoscaling client
client = boto3.client('autoscaling')
# ask user for the service / ASG they need the launch config for
new_service = input('Please enter the auto-scaling group name: ')

# bring in all of the auto scaling groups
groups = client.describe_auto_scaling_groups()

# loop through the groups and find the ASG that matches the user input
for group in groups['AutoScalingGroups']:
    if group['AutoScalingGroupName'] == new_service:
        # set variable to the name of that matching ASG
        launch_config_name = group['LaunchConfigurationName']
        break

# bring in the launch config that matches the ASG
launch_config = client.describe_launch_configurations(
    LaunchConfigurationNames = [launch_config_name]
)

# print out the launch config that matched
print("\n")
pprint("Launch configuration for the " + new_service + " auto scaling group is:")
pprint("---------------------------------------------------------------------")
pprint(launch_config['LaunchConfigurations'])