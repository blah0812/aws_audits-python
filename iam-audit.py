import os
import boto3
import csv
import time
from io import StringIO
from prettytable import PrettyTable
from datetime import datetime, timedelta
import pandas as pd
from pandas import ExcelWriter
from pandas import ExcelFile
import numpy as np
import xlsxwriter

# Tests
# ===========================================
# MFA device not activated
# Access keys older than 90 days
# User has not logged in more than 180 days

def get_users_from_cred_report():
    iam = get_iam_client(os.environ.get('AWS_ROLE_ARN'))

    print("Generating credential report")
    iam.generate_credential_report()

    print("Sleeping for 60 seconds")
    time.sleep(60)

    userList = []

    #Get credential report now
    print("Getting credential report")
    credential_report = iam.get_credential_report()
    userdata = StringIO(credential_report['Content'].decode('utf-8'))

    # Convert bytes to CSV
    reader = csv.DictReader(userdata, delimiter=',')

    for line in reader:    
        userList.append(line)

    return userList


class IAMUser(object):
    DATE_FORMAT = '%Y-%m-%dT%H:%M:%S+00:00'

    def __init__(self, data):
        self.data = data
        self.mfa_active = self._parse_bool(data['mfa_active'])
        self.name = data['user']
        self.created_at = self._parse_date(data['user_creation_time'])

        self.password_enabled = self._parse_bool(data['password_enabled'])
        self.password_last_used = self._parse_date(data['password_last_used'])
        self.password_last_changed = self._parse_date(data['password_last_changed'])

        self.access_key_1_active = self._parse_bool(data['access_key_1_active'])
        self.access_key_1_last_used = self._parse_date(data['access_key_1_last_used_date'])
        self.access_key_1_last_rotated = self._parse_date(data['access_key_1_last_rotated'])

        self.access_key_2_active = self._parse_bool(data['access_key_2_active'])
        self.access_key_2_last_used = self._parse_date(data['access_key_2_last_used_date'])
        self.access_key_2_last_rotated = self._parse_date(data['access_key_2_last_rotated'])

    def _parse_bool(self, boolstring):
        if boolstring in ['true', 'TRUE']:
            return True
        else:
            return False

    def _parse_date(self, datestring):
        epoch = datetime.fromtimestamp(0)
        return (epoch if (datestring in ['N/A','no_information','not_supported'])
                else datetime.strptime(datestring, self.DATE_FORMAT))

    def has_no_mfa(self):
        return self.password_enabled and not self.mfa_active
        
    def has_old_access_keys(self, days=90):
        inactive_date = datetime.now() - timedelta(days=days)
        if (self.created_at < inactive_date and (self.access_key_1_active and self.access_key_1_last_rotated < inactive_date) or (self.access_key_2_active and self.access_key_2_last_rotated < inactive_date)):
            return True

        return False

    def is_inactive(self, days=180):
        inactive_date = datetime.now() - timedelta(days=days)
        if (self.password_enabled and
                self.created_at < inactive_date and
                self.password_last_used < inactive_date and
                self.access_key_1_last_used < inactive_date and
                self.access_key_2_last_used < inactive_date):
            return True

        return False

def get_iam_client(roleArn=None):
    sts = boto3.client("sts")

    if roleArn:
        assumedRoleObject = sts.assume_role(
            RoleArn=os.environ['AWS_ROLE_ARN'],
            RoleSessionName="awssdk"
        )

        credentials = assumedRoleObject['Credentials']

        return boto3.client(
            'iam',
            aws_access_key_id = credentials['AccessKeyId'],
            aws_secret_access_key = credentials['SecretAccessKey'],
            aws_session_token = credentials['SessionToken'],
        )
    else:
        return boto3.client("iam")
    
def main():
    user_report = get_users_from_cred_report()
   
    control_data = pd.DataFrame([], columns=['Username', 'Rule Violations'])
    raw_data =pd.DataFrame([], columns=[
        'user',
        'arn',
        'user_creation_time',
        'password_enabled',
        'password_last_used',
        'password_last_changed',
        'password_next_rotation',
        'mfa_active',
        'access_key_1_active',
        'access_key_1_last_rotated',
        'access_key_1_last_used_date',
        'access_key_1_last_used_region',
        'access_key_1_last_used_service',
        'access_key_2_active',
        'access_key_2_last_rotated',
        'access_key_2_last_used_date',
        'access_key_2_last_used_region',
        'access_key_2_last_used_service',
        'cert_1_active',
        'cert_1_last_rotated',
        'cert_2_active',
        'cert_2_last_rotated'
    ]) 

    writer = pd.ExcelWriter("iam-audit.xlsx", engine='xlsxwriter')

    for user_data in user_report:
        user = IAMUser(user_data)
        
        raw_data = raw_data.append(user_data, ignore_index=True)

        access_key_max_age = int(os.environ.get('AUDIT_ACCESS_KEY_MAX_AGE', '90'))
        inactive_user_max_age = int(os.environ.get('AUDIT_INACTIVE_USERS_MAX_AGE', '180'))
        
        if user.has_no_mfa() or user.has_old_access_keys(days=access_key_max_age) or user.is_inactive(days=inactive_user_max_age):
            rule_violations =[]
            row = {
                "Username": user.name
            }

            if user.has_no_mfa():
                rule_violations.append("User has not activated MFA device")
            
            if user.has_old_access_keys(days=access_key_max_age):
                rule_violations.append("User has access keys older than {} days".format(access_key_max_age))

            if user.is_inactive(days=inactive_user_max_age):
                rule_violations.append("User has not logged over last {} days".format(inactive_user_max_age))

            row["Violations"] = rule_violations
            control_data = control_data.append({
                'Username': user.name,
                'Rule Violations': "\n".join(rule_violations)
            }, ignore_index=True)

    
    control_data.to_excel(writer, sheet_name='Audit Results', index=False)
    raw_data.to_excel(writer, sheet_name='IAM User Report', index=False)
    workbook = writer.book
    worksheet = writer.sheets['Audit Results']
    cell_format = workbook.add_format({
        'text_wrap': True,
        'valign': 'top'
    })
    worksheet.set_column('A:A', 50, cell_format)
    worksheet.set_column('B:B', 100, cell_format)
    writer.save()

if __name__ == '__main__':
    main()
