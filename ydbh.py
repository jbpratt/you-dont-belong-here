#!/bin/python3
"""
Find policies in an organization that allow outside entities access to services (maybe unknowingly)
"""

from typing import Dict, List
import argparse

import boto3
from botocore.exceptions import ClientError

# TODO: Get all inline policies

def discovery(acct: Dict, role: str) -> None:
    sts_client = boto3.client('sts')
    _id = acct['id']
    try:
        creds = sts_client.assume_role(
            RoleArn=f"arn:aws:iam::{_id}:role/{role}",
            RoleSessionName=f"{_id}-{role}"
        )['Credentials']
    except ClientError as ex:
        raise ex
    # load all groups
    iam = boto3.client(
        'iam',
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretAccessKey'],
        aws_session_token=creds['SessionToken'],
    )

    policies = None
    try:
        response = iam.list_policies(
            Scope='Local'
        )
        policies = response['Policies']
        while response['IsTruncated']:
            try:
                response = iam.list_policies(
                    Scope='Local',
                    Marker=response['Marker']
                )
                policies.append(response['Policies'])
            except ClientError as ex:
                raise ex
    except ClientError as ex:
        raise ex

    # look for allowed account numbers not in the allowed list
    for policy in policies:
        policy_arn_acct_id = policy['Arn'][13:25]
        if policy_arn_acct_id != _id:
            print(f"Found a policy not belonging to {_id}")
            print(policy)


ORGS = boto3.client('organizations')

PARSER = argparse.ArgumentParser(description='')
PARSER.add_argument(
        '-org-role',
        dest='ROLE',
        type=str,
        default='OrganizationAccountAccessRole',
        help='role to assume within account'
)
ARGS = PARSER.parse_args()

ACCTS: List = []
try:
    RESPONSE = ORGS.list_accounts()
    for account in RESPONSE['Accounts']:
        ACCTS.append(account)

    while RESPONSE['NextToken']:
        try:
            RESPONSE = ORGS.list_accounts(
                NextToken=RESPONSE['NextToken']
            )
            for account in RESPONSE['Accounts']:
                ACCTS.append(account)
        except ClientError as ex:
            raise ex
except ClientError as ex:
    raise ex

for account in ACCTS:
    discovery(acct=account, role=ARGS.ROLE)
