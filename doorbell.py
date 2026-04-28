import boto3
import json
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

cloudtrail = boto3.client('cloudtrail', region_name=os.getenv('AWS_REGION'))
ses = boto3.client('ses', region_name=os.getenv('AWS_REGION'))

SUSPICIOUS_EVENTS = [
    'ConsoleLogin',
    'GetSecretValue',
    'DeleteTrail',
    'StopLogging',
    'DeleteBucket',
    'PutBucketPolicy',
    'CreateUser',
    'AttachUserPolicy',
    'AttachRolePolicy',
    'CreateAccessKey',
    'UpdateAccountPasswordPolicy'
]

def get_recent_events(hours=24):
    print(f"🔍 Scanning CloudTrail for last {hours} hours...\n")
    
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=hours)
    
    events = []
    paginator = cloudtrail.get_paginator('lookup_events')
    
    for page in paginator.paginate(
        StartTime=start_time,
        EndTime=end_time,
        LookupAttributes=[{
            'AttributeKey': 'ReadOnly',
            'AttributeValue': 'false'
        }]
    ):
        events.extend(page.get('Events', []))
    
    return events

def analyze_events(events):
    print(f"Analyzing {len(events)} events...\n")
    
    suspicious = []
    console_logins = []
    root_activity = []
    
    for event in events:
        event_name = event.get('EventName', '')
        username = event.get('Username', 'unknown')
        event_time = event.get('EventTime', '')
        source_ip = 'unknown'
        
        # Get source IP from CloudTrail record
        if event.get('CloudTrailEvent'):
            try:
                detail = json.loads(event['CloudTrailEvent'])
                source_ip = detail.get('sourceIPAddress', 'unknown')
            except:
                pass
        
        # Check for console logins
        if event_name == 'ConsoleLogin':
            console_logins.append({
                'event': event_name,
                'user': username,
                'time': str(event_time),
                'source_ip': source_ip,
                'severity': 'INFO'
            })
            print(f"🔑 Console login: {username} from {source_ip}")
        
        # Check for root activity
        if username == 'root':
            root_activity.append({
                'event': event_name,
                'user': username,
                'time': str(event_time),
                'source_ip': source_ip,
                'severity': 'CRITICAL'
            })
            print(f"🚨 ROOT activity: {event_name} from {source_ip}")
        
        # Check for suspicious events
        if event_name in SUSPICIOUS_EVENTS and event_name != 'ConsoleLogin':
            suspicious.append({
                'event': event_name,
                'user': username,
                'time': str(event_time),
                'source_ip': source_ip,
                'severity': 'HIGH' if event_name in [
                    'DeleteTrail', 'StopLogging', 'CreateUser', 'CreateAccessKey'
                ] else 'MEDIUM'
            })
            print(f"⚠️ Suspicious: {event_name} by {username}")
    
    return {
        'console_logins': console_logins,
        'root_activity': root_activity,
        'suspicious_events': suspicious,
        'total_events_scanned': len(events),
        'risk_level': 'CRITICAL' if root_activity else 'HIGH' if suspicious else 'LOW'
    }

def send_security_alert(analysis):
    risk_emoji = '🚨' if analysis['risk_level'] == 'CRITICAL' else '⚠️' if analysis['risk_level'] == 'HIGH' else '✅'
    
    message = f"""
SECURITY DOORBELL ALERT 🔔
===========================
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Risk Level: {risk_emoji} {analysis['risk_level']}

SUMMARY:
Total Events Scanned: {analysis['total_events_scanned']}
Console Logins: {len(analysis['console_logins'])}
Root Activity: {len(analysis['root_activity'])}
Suspicious Events: {len(analysis['suspicious_events'])}

CONSOLE LOGINS:
{chr(10).join([f"🔑 {e['user']} from {e['source_ip']} at {e['time']}" for e in analysis['console_logins']]) or 'None detected'}

ROOT ACTIVITY:
{chr(10).join([f"🚨 {e['event']} from {e['source_ip']} at {e['time']}" for e in analysis['root_activity']]) or 'None detected'}

SUSPICIOUS EVENTS:
{chr(10).join([f"⚠️ {e['severity']}: {e['event']} by {e['user']} at {e['time']}" for e in analysis['suspicious_events']]) or 'None detected'}

{'🚨 IMMEDIATE ACTION REQUIRED' if analysis['risk_level'] == 'CRITICAL' else '⚠️ Review suspicious activity' if analysis['risk_level'] == 'HIGH' else '✅ No immediate action required'}

Security Doorbell 🔔
    """

    subject = f"{risk_emoji} AWS Security Alert — Risk Level: {analysis['risk_level']}"

    ses.send_email(
        Source=os.getenv('YOUR_EMAIL'),
        Destination={'ToAddresses': [os.getenv('YOUR_EMAIL')]},
        Message={
            'Subject': {'Data': subject},
            'Body': {'Text': {'Data': message}}
        }
    )
    print(f"\n📧 Security alert sent to {os.getenv('YOUR_EMAIL')}")

def run():
    print("🔔 Security Doorbell")
    print("====================\n")

    # Step 1 — Get recent events
    print("Step 1: Scanning CloudTrail events...")
    events = get_recent_events(hours=24)

    # Step 2 — Analyze events
    print("Step 2: Analyzing for suspicious activity...")
    analysis = analyze_events(events)

    print(f"\n📊 SECURITY SUMMARY:")
    print(f"Risk Level: {analysis['risk_level']}")
    print(f"Console Logins: {len(analysis['console_logins'])}")
    print(f"Root Activity: {len(analysis['root_activity'])}")
    print(f"Suspicious Events: {len(analysis['suspicious_events'])}")

    # Step 3 — Send alert
    print("\nStep 3: Sending security alert...")
    send_security_alert(analysis)

    # Save report
    with open('security_report.json', 'w') as f:
        json.dump(analysis, f, indent=2, default=str)

    print("📄 Report saved to security_report.json")
    print("\n✅ Security Doorbell complete!")

if __name__ == "__main__":
    run()