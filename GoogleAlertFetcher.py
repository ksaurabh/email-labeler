import os
import base64
from google.oauth2 import service_account
from googleapiclient.discovery import build
from datetime import datetime, timedelta

# Configuration
SERVICE_ACCOUNT_FILE = 'alertfetcher-474421-dc82980ebf9e.json'
SCOPES = ['https://www.googleapis.com/auth/apps.alerts']
DELEGATED_USER = 'kumar@airmdr.com'  # Admin user to impersonate
GMAIL_SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def get_alert_center_service():
    """Create and return Alert Center API service."""
    credentials = service_account.Credentials.from_service_account_file(
        SERVICE_ACCOUNT_FILE,
        scopes=SCOPES
    )

    # Delegate credentials to admin user
    delegated_credentials = credentials.with_subject(DELEGATED_USER)

    service = build('alertcenter', 'v1beta1', credentials=delegated_credentials)
    return service


def fetch_alerts(service, page_size=100, filter_query=None):
    """
    Fetch alerts from Google Workspace Alert Center.

    Args:
        service: Alert Center API service
        page_size: Number of alerts per page (max 100)
        filter_query: Optional filter string (e.g., "createTime >= \"2024-01-01T00:00:00Z\"")

    Returns:
        List of alert dictionaries
    """
    alerts = []
    page_token = None

    try:
        while True:
            # Build request
            request_params = {
                'pageSize': page_size,
                'pageToken': page_token
            }

            if filter_query:
                request_params['filter'] = filter_query

            # Execute request
            response = service.alerts().list(**request_params).execute()

            # Add alerts to list
            if 'alerts' in response:
                alerts.extend(response['alerts'])
                print(f"Fetched {len(response['alerts'])} alerts...")

            # Check for next page
            page_token = response.get('nextPageToken')
            if not page_token:
                break

    except Exception as e:
        print(f"Error fetching alerts: {e}")
        raise

    return alerts


def get_alert_details(service, alert_id):
    """Get detailed information for a specific alert."""
    try:
        alert = service.alerts().get(alertId=alert_id).execute()
        return alert
    except Exception as e:
        print(f"Error fetching alert {alert_id}: {e}")
        return None


def print_alert_summary(alerts):
    """Print a summary of alerts."""
    print(f"\n{'=' * 80}")
    print(f"Total Alerts: {len(alerts)}")
    print(f"{'=' * 80}\n")

    for i, alert in enumerate(alerts, 1):
        print(f"Alert {i}:")
        print(f"  ID: {alert.get('alertId', 'N/A')}")
        print(f"  Type: {alert.get('type', 'N/A')}")
        print(f"  Source: {alert.get('source', 'N/A')}")
        print(f"  Create Time: {alert.get('createTime', 'N/A')}")
        print(f"  Start Time: {alert.get('startTime', 'N/A')}")

        # Print metadata if available
        if 'data' in alert:
            print(f"  Data: {alert['data']}")

        print()



def get_gmail_service(user_email):
    """Create and return Gmail API service for a specific user."""
    credentials = service_account.Credentials.from_service_account_file(
        SERVICE_ACCOUNT_FILE,
        scopes=GMAIL_SCOPES
    )

    # Delegate credentials to the specific user
    delegated_credentials = credentials.with_subject(user_email)

    service = build('gmail', 'v1', credentials=delegated_credentials)
    return service


def get_message_body(service, message_id):
    """
    Fetch the full message body given a message ID.

    Args:
        service: Gmail API service
        message_id: The Gmail message ID

    Returns:
        Dictionary with message details including body
    """
    try:
        # Get the full message
        message = service.users().messages().get(
            userId='me',
            id=message_id,
            format='full'  # 'full' gives complete message with headers and body
        ).execute()

        # Extract message details
        headers = message['payload']['headers']
        subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), 'No Subject')
        from_email = next((h['value'] for h in headers if h['name'].lower() == 'from'), 'Unknown')
        date = next((h['value'] for h in headers if h['name'].lower() == 'date'), 'Unknown')

        # Extract body
        body = extract_message_body(message['payload'])

        return {
            'id': message_id,
            'subject': subject,
            'from': from_email,
            'date': date,
            'snippet': message.get('snippet', ''),
            'body': body,
            'headers': headers,
            'raw_message': message
        }

    except Exception as e:
        print(f"Error fetching message {message_id}: {e}")
        return None


def extract_message_body(payload):
    """
    Extract the message body from the payload.
    Handles both plain text and HTML, and multipart messages.
    """
    body_data = {
        'text': '',
        'html': ''
    }

    # Check if body is directly in payload
    if 'body' in payload and 'data' in payload['body']:
        mime_type = payload.get('mimeType', '')
        decoded_body = base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8')

        if 'text/plain' in mime_type:
            body_data['text'] = decoded_body
        elif 'text/html' in mime_type:
            body_data['html'] = decoded_body

        return body_data

    # Handle multipart messages
    if 'parts' in payload:
        for part in payload['parts']:
            mime_type = part.get('mimeType', '')

            # Recursively handle nested parts
            if 'parts' in part:
                nested_body = extract_message_body(part)
                if nested_body['text']:
                    body_data['text'] += nested_body['text']
                if nested_body['html']:
                    body_data['html'] += nested_body['html']

            # Extract body from this part
            elif 'body' in part and 'data' in part['body']:
                try:
                    decoded_body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')

                    if 'text/plain' in mime_type:
                        body_data['text'] += decoded_body
                    elif 'text/html' in mime_type:
                        body_data['html'] += decoded_body
                except Exception as e:
                    print(f"Error decoding part: {e}")

    return body_data


def get_message_raw(service, message_id):
    """
    Get the raw RFC 2822 formatted email message.
    Useful for full message inspection including all headers.
    """
    try:
        message = service.users().messages().get(
            userId='me',
            id=message_id,
            format='raw'
        ).execute()

        # Decode the raw message
        raw_message = base64.urlsafe_b64decode(message['raw']).decode('utf-8')
        return raw_message

    except Exception as e:
        print(f"Error fetching raw message {message_id}: {e}")
        return None


def find_gmail_message_id(service, message_id_header):
    """
    Find Gmail's internal message ID using the Message-ID header.

    Args:
        service: Gmail API service
        message_id_header: The Message-ID from email headers (e.g., "123@example.com")

    Returns:
        Gmail's internal message ID or None if not found
    """
    try:
        # Search for the message using the Message-ID header
        # Gmail search supports rfc822msgid: operator
        query = f'rfc822msgid:{message_id_header}'

        results = service.users().messages().list(
            userId='me',
            q=query,
            includeSpamTrash=True,
            maxResults=1
        ).execute()

        messages = results.get('messages', [])

        if messages:
            gmail_id = messages[0]['id']
            print(f"Found Gmail ID: {gmail_id} for Message-ID: {message_id_header}")
            return gmail_id
        else:
            print(f"No message found with Message-ID: {message_id_header}")
            return None

    except Exception as e:
        print(f"Error searching for message {message_id_header}: {e}")
        return None

def fetch_phishing_messages_with_bodies(alert_center_service, gmail_service_func):
    """
    Complete workflow: Fetch phishing alerts and get message bodies.

    Args:
        alert_center_service: Alert Center API service
        gmail_service_func: Function to get Gmail service for a user
    """
    # Get phishing alerts
    filter_query = 'type = "User reported phishing"'
    alerts = fetch_alerts(alert_center_service, filter_query=filter_query)

    print(f"Found {len(alerts)} phishing alerts\n")

    for alert in alerts[:1]:
        print(f"\n{'=' * 80}")
        print(f"Alert ID: {alert['alertId']}")

        if 'data' in alert:
            data = alert['data']

            # Get messages from alert
            messages = data.get('messages', [])

            for msg in messages:
                print(msg)
                message_id = msg.get('messageId')
                recipient = msg.get('recipient')
                if not message_id or not recipient:
                    continue

                print(f"\nMessage ID: {message_id}")
                print(f"Recipient: {recipient}")

                # Get Gmail service for the recipient
                try:
                    gmail_service = gmail_service_func(recipient)

                    print("Find gmail message id:")
                    gmail_message_id = find_gmail_message_id(gmail_service, message_id)
                    print("GMail MEssage id:" +  gmail_message_id)



                    # Fetch the message body
                    message_details = get_message_body(gmail_service, gmail_message_id)

                    if message_details:
                        print(f"Subject: {message_details['subject']}")
                        print(f"From: {message_details['from']}")
                        print(f"Date: {message_details['date']}")
                        print(f"\n--- Message Body (Text) ---")
                        print(message_details['body']['text'][:500])  # First 500 chars

                        if message_details['body']['html']:
                            print(f"\n--- Message Body (HTML) ---")
                            print(message_details['body']['html'][:500])  # First 500 chars

                except Exception as e:
                    print(f"Error accessing mailbox for {recipient}: {e}")


# Complete example usage
def main():
    # Setup Alert Center service
    alert_credentials = service_account.Credentials.from_service_account_file(
        SERVICE_ACCOUNT_FILE,
        scopes=['https://www.googleapis.com/auth/apps.alerts']
    )
    alert_delegated = alert_credentials.with_subject(DELEGATED_USER)
    alert_service = build('alertcenter', 'v1beta1', credentials=alert_delegated)

    # Function to create Gmail service for any user
    def get_gmail_for_user(user_email):
        return get_gmail_service(user_email)

    # Fetch phishing alerts and their message bodies
    fetch_phishing_messages_with_bodies(alert_service, get_gmail_for_user)


if __name__ == '__main__':
    main()

