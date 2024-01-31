#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import time
import requests
import os
import json
from email.message import EmailMessage
import base64
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging

# Email configuration
EMAIL_FROM = "<your send email address>" # must be a valid email box allowed to send
EMAIL_TO = "your recipient email" #ideally a ticketing system inbox 
ALERT_THRESHOLD = 300 # time in seconds between alert batches being sent, as long as there is 1 alert in the batch
ALERT_BATCH_SIZE = 30 # size alert batch hits to trigger an immediate email without waiting for alert threshold timer
ALERT_SUPPRESSION_TIME = 600 # Duplicate alerts will not be added to alet batch for this many seconds
LOG_FILE_PATH = "/var/log/suricata/eve.json"

# Azure AD credentials
client_id = os.environ['AZURE_CLIENT_ID'] # as defined curing docker-compose
client_secret = os.environ['AZURE_CLIENT_SECRET'] # as defined curing docker-compose
tenant_id = os.environ['AZURE_TENANT_ID'] # as defined curing docker-compose
scope = 'https://graph.microsoft.com/.default'
grant_type = 'client_credentials'

logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    filename='/var/log/suricata/tripwire_log.log', 
                    filemode='a')



def get_token():
    token_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'
    token_data = {
        'client_id': client_id,
        'scope': scope,
        'client_secret': client_secret,
        'grant_type': grant_type
    }
    token_r = requests.post(token_url, data=token_data)
    token_r.raise_for_status()
    return token_r.json().get('access_token')

def send_to_email(alert_batch):
    token = get_token()
    message = EmailMessage()
    
    # Create an email body with structured alert data
    alert_details = []
    for alert in alert_batch:
        alert_details.append(
            f"Severity: {alert['severity']} | "
            f"Timestamp: {alert['timestamp']} | "
            f"Signature: {alert['signature']} | "
            f"Source IP: {alert['src_ip']}:{alert['src_port']} | "
            f"Destination IP: {alert['dest_ip']}:{alert['dest_port']} | "
            f"Protocol: {alert['protocol']}"
        )
    
    message.set_content("Suricata Alerts:\n\n" + "\n\n".join(alert_details))
    message['Subject'] = "Suricata Alert Notification"
    message['From'] = EMAIL_FROM
    message['To'] = EMAIL_TO

    payload = {
        'message': {
            'subject': message['Subject'],
            'body': {
                'contentType': 'Text',
                'content': message.get_content()
            },
            'toRecipients': [{'emailAddress': {'address': EMAIL_TO}}],
            'from': {'emailAddress': {'address': EMAIL_FROM}}
        },
        'saveToSentItems': 'true'
    }

    graph_url = f'https://graph.microsoft.com/v1.0/users/{EMAIL_FROM}/sendMail'
    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
    response = requests.post(graph_url, headers=headers, json=payload)
    response.raise_for_status()
    logging.info("Email sent successfully.")


def parse_alert(json_line):
    try:
        alert = json.loads(json_line)
        if alert.get('alert', {}).get('severity', 3) <= 1:
            parsed_alert = {
                'signature': alert['alert']['signature'],
                'src_ip': alert['src_ip'],
                'src_port': alert.get('src_port', 'N/A'),
                'dest_ip': alert['dest_ip'],
                'dest_port': alert.get('dest_port', 'N/A'),
                'protocol': alert.get('proto', 'N/A'),
                'timestamp': alert['timestamp'],
                'severity': alert['alert'].get('severity', 'N/A')
            }
            logging.info(f"Alert parsed: {parsed_alert}")
            return parsed_alert
    except json.JSONDecodeError:
        logging.error("Failed to decode JSON line.")
    return None


#define global variables for timing, don't touch
alert_batch = []
last_send_time = time.time()
last_alert_sent_time = {}
last_read_position = 0
last_inode_number = None

def get_inode_number(file_path):
    try:
        return os.stat(file_path).st_ino
    except FileNotFoundError:
        logging.error(f"An error occurred: file not found")
        return None

class LogFileHandler(FileSystemEventHandler):
    def on_modified(self, event):
        # Check if the event is for a file and not a directory
        if not event.is_directory:
            # Check if the modified file is 'eve.json'
            if os.path.basename(event.src_path) == 'eve.json':
                process_log_file()

def process_log_file():
    global last_send_time
    global last_alert_sent_time  
    global alert_batch 
    global last_read_position
    global last_inode_number
    
    current_inode_number = get_inode_number(LOG_FILE_PATH)

    # Check if the file has been rotated
    if current_inode_number != last_inode_number:
        # File has been rotated, start from the beginning of the new file
        last_read_position = 0
        last_inode_number = current_inode_number

    try:
        with open(LOG_FILE_PATH, "r") as log_file:
            log_file.seek(last_read_position)
            for line in log_file:
                alert = parse_alert(line)
                if alert:
                    # Create a unique key for the alert to check for duplicates
                    alert_key = (alert['signature'], alert['src_ip'], alert['dest_ip'])
                    
                    current_time = time.time()
                    # Check if the alert has been sent recently
                    if last_alert_sent_time.get(alert_key, 0) + ALERT_SUPPRESSION_TIME < current_time:
                        alert_batch.append(alert)
                        # Update the time the alert was last sent
                        last_alert_sent_time[alert_key] = current_time
            
            last_read_position = log_file.tell()

        # After reading new lines, check if it's time to send an email outside the loop
        current_time = time.time()
        if len(alert_batch) >= ALERT_BATCH_SIZE or (current_time - last_send_time) > ALERT_THRESHOLD:
            if alert_batch:  # Ensure there are new alerts to send
                send_to_email(alert_batch)
                alert_batch.clear()  # Reset the alert batch after sending the email
                last_send_time = current_time

        logging.info(f"Processing log file. Current batch size: {len(alert_batch)}")
    except Exception as e:
        logging.error(f"An error occurred: {e}")

#run continuously unless stopped
if __name__ == "__main__":
    observer = Observer()
    observer.schedule(LogFileHandler(), path=os.path.dirname(LOG_FILE_PATH), recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
