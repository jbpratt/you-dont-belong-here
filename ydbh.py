#!/bin/python3
"""
Find policies in an account that allow outside entities access to services (maybe unknowingly)
"""

import boto3
from botocore.exceptions import ClientError

# TODO: Get all inline policies

ORGS = boto3.client('organizations')
IAM = boto3.client('iam')

ACCT_IDS = []
try:
    RESPONSE = ORGS.list_accounts()
    for account in RESPONSE['Accounts']:
        ACCT_IDS.append(account['id'])

    while RESPONSE['NextToken']:
        try:
            RESPONSE = ORGS.list_accounts(
                NextToken=RESPONSE['NextToken']
            )
            for account in RESPONSE['Accounts']:
                ACCT_IDS.append(account['id'])
        except ClientError as ex:
            raise ex
except ClientError as ex:
    raise ex


# load all groups
ARNS = []
try:
    RESPONSE = IAM.list_groups()
    for group in RESPONSE['Groups']:
        ARNS.append(group['Arn'][13:25])

    while RESPONSE['IsTruncated']:
        try:
            RESPONSE = IAM.list_groups(
                Marker=RESPONSE['Marker']
            )
            for group in RESPONSE['Groups']:
                ARNS.append(group['Arn'][13:25])
        except ClientError as ex:
            raise ex
except ClientError as ex:
    raise ex

# load all users
try:
    USERS = None
    RESPONSE = IAM.list_users()
    for user in RESPONSE['Users']:
        ARNS.append(user['Arn'][13:25])

    while RESPONSE['IsTruncated']:
        try:
            RESPONSE = IAM.list_users(
                Marker=RESPONSE['Marker']
            )
            for user in RESPONSE['Users']:
                ARNS.append(user['Arn'][13:25])
        except ClientError as ex:
            raise ex
except ClientError as ex:
    raise ex

# load all roles
try:
    ROLES = None
    RESPONSE = IAM.list_roles()
    for role in RESPONSE['Roles']:
        ARNS.append(role['Arn'][13:25])

    while RESPONSE['IsTruncated']:
        try:
            RESPONSE = IAM.list_roles(
                Marker=RESPONSE['Marker']
            )
            for role in RESPONSE['Roles']:
                ARNS.append(role['Arn'][13:25])
        except ClientError as ex:
            raise ex
except ClientError as ex:
    raise ex

# load all policies
POLICIES = None
try:
    RESPONSE = IAM.list_policies(
        Scope='Local'
    )
    POLICIES = RESPONSE['Policies']
    while RESPONSE['IsTruncated']:
        try:
            RESPONSE = IAM.list_policies(
                Scope='Local',
                Marker=RESPONSE['Marker']
            )
            POLICIES.append(RESPONSE['Policies'])
        except ClientError as ex:
            raise ex
except ClientError as ex:
    raise ex


# look for allowed account numbers not in the allowed list
for policy in POLICIES:
    policy_arn_acct_id = policy['Arn'][13:25]
    for arn in ARNS:
        if policy_arn_acct_id != arn:
            print('Found a policy')
            print(policy)

"""
for policy in POLICIES:
    policy_arn_acct_id = policy['Arn'][13:25]
    for acct_id in ACCT_IDS:
        if policy_arn_acct_id != acct_id:
            print('Found a policy')
            print(policy)
"""
