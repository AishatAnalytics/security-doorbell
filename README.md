# Security Doorbell 🔔

Real-time AWS security monitoring that detects suspicious logins and root activity instantly.

## The Problem
Someone logs into your AWS account from a new location. You find out 3 days later when you check CloudTrail manually. By then the damage is done.

## What It Does
- Scans CloudTrail events from the last 24 hours
- Detects console logins and their source IPs
- Flags root account activity immediately
- Identifies suspicious API calls
- Calculates overall risk level
- Sends detailed security alert via email

## Real Results
First run on my own AWS account found:
- Risk Level: CRITICAL
- 7 root activity events detected
- StopDBInstance called from IP 99.30.49.125
- All events traced back to legitimate RDS testing

## Tech Stack
- Python 3
- AWS CloudTrail
- AWS SES
- boto3

## Suspicious Events Monitored
- Console logins
- Root account activity
- DeleteTrail and StopLogging
- CreateUser and CreateAccessKey
- AttachUserPolicy and AttachRolePolicy
- DeleteBucket and PutBucketPolicy

## Key Concepts Demonstrated
- Real-time threat detection
- CloudTrail event analysis
- AWS Well-Architected Security Pillar
- GuardDuty and Security Hub patterns

## How To Run
- Clone the repo
- pip install boto3 python-dotenv
- Add your AWS credentials and email to .env
- Run py doorbell.py

## Part of my 30 cloud projects in 30 days series
Follow along: https://www.linkedin.com/in/aishatolatunji/