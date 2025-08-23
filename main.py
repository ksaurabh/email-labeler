import os
import pickle
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from collections import Counter
import GoogleDriveCSVDownloader
import GoogleCSVSheetDownloader
from email.utils import parseaddr
from datetime import datetime, timedelta
import csv
from email.utils import parseaddr

def get_domain(email_str):
    return parseaddr(email_str)[1].split('@')[1] if '@' in parseaddr(email_str)[1] else None

# Usage
domain = get_domain("Kumar Saurabh <kumar@airmdr.com>")

def csv_to_dict_list(file_path):
    """Convert CSV to list of dictionaries (each row is a dict)."""
    result = []

    with open(file_path, 'r', newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)

        for row in reader:
            result.append(dict(row))

    return result


# Gmail API scope for reading and modifying emails
SCOPES = ['https://www.googleapis.com/auth/gmail.modify', 'https://www.googleapis.com/auth/spreadsheets.readonly']


class GmailLabeler:
    def __init__(self, credentials_file='credentials.json', token_file='token.pickle'):
        """
        Initialize the Gmail labeler with authentication credentials.

        Args:
            credentials_file: Path to the OAuth2 credentials JSON file
            token_file: Path to store the authentication token
        """
        self.credentials_file = credentials_file
        self.token_file = token_file
        self.service = None
        self.authenticate()

    def authenticate(self):
        """Authenticate with Gmail API using OAuth2."""
        creds = None

        # Load existing token if it exists
        if os.path.exists(self.token_file):
            with open(self.token_file, 'rb') as token:
                creds = pickle.load(token)

        # If there are no valid credentials, request authorization
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    self.credentials_file, SCOPES)
                creds = flow.run_local_server(port=0)

            # Save credentials for future use
            with open(self.token_file, 'wb') as token:
                pickle.dump(creds, token)

        # Build the Gmail service
        try:
            self.service = build('gmail', 'v1', credentials=creds)
            print("Successfully authenticated with Gmail API")
        except HttpError as error:
            print(f"An error occurred during authentication: {error}")
            return None

    def get_labels(self):
        """Get all available labels in the Gmail account."""
        try:
            results = self.service.users().labels().list(userId='me').execute()
            labels = results.get('labels', [])
            return labels
        except HttpError as error:
            print(f"An error occurred while fetching labels: {error}")
            return []

    def move_thread_to_inbox(self, thread_id: str, user_id: str = 'me') -> bool:
        """
        Move a Gmail thread to inbox by adding INBOX label.

        Args:
            service: Gmail API service object
            thread_id: ID of the thread to move to inbox
            user_id: Gmail user ID (default: 'me')

        Returns:
            bool: True if successful, False otherwise
        """
        service = self.service
        try:
            # Add INBOX label to the thread
            result = service.users().threads().modify(
                userId=user_id,
                id=thread_id,
                body={'addLabelIds': ['INBOX']}
            ).execute()

            print(f"Successfully moved thread {thread_id} to inbox")
            return True

        except HttpError as error:
            print(f"An error occurred: {error}")
            return False

    def remove_label_from_thread(self, thread_id: str, label_id, label_name,
                                 user_id: str = 'me') -> bool:
        """
        Remove specified labels from all messages in a Gmail thread.

        Args:
            service: Gmail API service object
            thread_id: ID of the thread to modify
            label_ids: List of label IDs to remove
            user_id: Gmail user ID (default: 'me')

        Returns:
            bool: True if successful, False otherwise
        """
        service = self.service
        try:
            # Modify the thread to remove labels
            result = service.users().threads().modify(
                userId=user_id,
                id=thread_id,
                body={'removeLabelIds': label_id}
            ).execute()

            print(f"Successfully removed label name={label_name}, id={label_id} from thread {thread_id}")
            return True

        except HttpError as error:
            print(f"An error occurred: {error}")
            return False

    def create_label(self, label_name):
        """
        Create a new label in Gmail.

        Args:
            label_name: Name of the label to create

        Returns:
            Label ID if successful, None otherwise
        """
        try:
            label_body = {
                'name': label_name,
                'labelListVisibility': 'labelShow',
                'messageListVisibility': 'show'
            }

            result = self.service.users().labels().create(
                userId='me', body=label_body).execute()
            print(f"Created label: {label_name}")
            return result['id']
        except HttpError as error:
            print(f"An error occurred while creating label: {error}")
            return None

    def search_emails(self, query, max_results=10):
        """
        Search for emails using Gmail search syntax.

        Args:
            query: Gmail search query (e.g., 'from:example@gmail.com')
            max_results: Maximum number of emails to return

        Returns:
            List of email IDs
        """
        try:
            results = self.service.users().messages().list(
                userId='me', q=query, maxResults=max_results).execute()
            messages = results.get('messages', [])
            return [msg['id'] for msg in messages]
        except HttpError as error:
            print(f"An error occurred while searching emails: {error}")
            return []

    def get_email_details(self, email_id):
        """
        Get details of a specific email.

        Args:
            email_id: Gmail message ID

        Returns:
            Email details dictionary
        """
        try:
            message = self.service.users().messages().get(
                userId='me', id=email_id).execute()

            # Extract basic information
            headers = message['payload'].get('headers', [])
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
            sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown Sender')

            return {
                'id': email_id,
                'subject': subject,
                'sender': sender,
                'labels': message.get('labelIds', [])
            }
        except HttpError as error:
            print(f"An error occurred while getting email details: {error}")
            return None

    def add_label_to_thread(self, thread_id, label_id):
        """Add label to a specific thread"""
        service = self.service
        try:
            # Get all messages in the thread
            thread = service.users().threads().get(
                userId='me', id=thread_id).execute()

            message_ids = [msg['id'] for msg in thread['messages']]

            # Apply label to all messages in thread
            body = {
                'ids': message_ids,
                'addLabelIds': [label_id]
            }

            result = service.users().messages().batchModify(
                userId='me', body=body).execute()

            print(f"Successfully added label to thread with {len(message_ids)} messages")
            return True

        except HttpError as error:
            print(f'An error occurred: {error}')
            return False

    def add_label_to_email(self, email_id, label_id):
        """
        Add a label to a specific email.

        Args:
            email_id: Gmail message ID
            label_id: Label ID to add

        Returns:
            True if successful, False otherwise
        """
        try:
            body = {'addLabelIds': [label_id]}
            self.service.users().messages().modify(
                userId='me', id=email_id, body=body).execute()
            return True
        except HttpError as error:
            print(f"An error occurred while adding label: {error}")
            return False

    def remove_label_from_email(self, email_id, label_id):
        """
        Remove a label from a specific email.

        Args:
            email_id: Gmail message ID
            label_id: Label ID to remove

        Returns:
            True if successful, False otherwise
        """
        try:
            body = {'removeLabelIds': [label_id]}
            self.service.users().messages().modify(
                userId='me', id=email_id, body=body).execute()
            print(f"Removed label from email {email_id}")
            return True
        except HttpError as error:
            print(f"An error occurred while removing label: {error}")
            return False

    def bulk_label_emails(self, search_query, label_name, max_emails=50):
        """
        Apply a label to multiple emails matching a search query.

        Args:
            search_query: Gmail search query
            label_name: Name of the label to apply
            max_emails: Maximum number of emails to process

        Returns:
            Number of emails successfully labeled
        """
        # Get or create the label
        labels = self.get_labels()
        label_id = None

        for label in labels:
            if label['name'] == label_name:
                label_id = label['id']
                break

        if not label_id:
            label_id = self.create_label(label_name)
            if not label_id:
                print(f"Failed to create label: {label_name}")
                return 0

        # Search for emails
        email_ids = self.search_emails(search_query, max_emails)

        if not email_ids:
            print(f"No emails found matching query: {search_query}")
            return 0

        # Apply label to each email
        success_count = 0
        for email_id in email_ids:
            email_details = self.get_email_details(email_id)
            if email_details:
                print(f"Processing: {email_details['subject'][:50]}...")
                if self.add_label_to_email(email_id, label_id):
                    success_count += 1

        print(f"Successfully labeled {success_count} out of {len(email_ids)} emails")
        return success_count

    def priority_by_email(self, priorities, email):
        for p in priorities:
            if p['from'].lower() == email.lower():
                return f"p{p['priority']}"
        return "p_unknown"

    def mark_thread_as_read(self, thread_id: str, user_id: str = 'me') -> bool:
        """
        Mark a Gmail thread as read by removing the UNREAD label.

        Args:
            service: Gmail API service object
            thread_id: ID of the thread to mark as read
            user_id: Gmail user ID (default: 'me')

        Returns:
            bool: True if successful, False otherwise
        """
        service = self.service
        try:
            # Remove UNREAD label from the thread
            result = service.users().threads().modify(
                userId=user_id,
                id=thread_id,
                body={'removeLabelIds': ['UNREAD']}
            ).execute()

            print(f"Successfully marked thread {thread_id} as read")
            return True

        except HttpError as error:
            print(f"An error occurred: {error}")
            return False

    def label_id(self, label_name, labels):
        for label in labels:
            if label['name'] == label_name:
                return label['id']
        return label_name

    def remove_priority_labels(self, labels):
        plabels = ["p0", "p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8", "p9", "p10"]
        for plabel in plabels:
            label_id = self.label_id(plabel, labels)
            thread_ids = self.search_threads(f"label:inbox label:{plabel}", 10000)
            print(f"Found {len(thread_ids)} threads with label.name={plabel}")
            threads = 0
            totalThreads = len(thread_ids)
            for thread_id in thread_ids:
                self.remove_label_from_thread(thread_id, label_id, plabel)
                threads += 1
                print(f"Updated {threads}/{totalThreads} threads")

    def count_by_priority_labels(self, labels):
        plabels = ["p0", "p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8", "p9", "p10", "p_unknown", "@ReadyToArchive"]
        for plabel in plabels:
            label_id = self.label_id(plabel, labels)
            thread_ids = self.search_threads(f"label:inbox label:{plabel}", 10000)
            print(f"Found {len(thread_ids)} threads with label.name={plabel}")
            if plabel == "p_unknown":
                unknown_senders = set()
                for thread_id in thread_ids:
                    thread = self.get_thread_details(thread_id)
                    sender = self.getSenderFromThreadDetails(thread)
                    name, thread = parseaddr(sender)
                    unknown_senders.add(thread)

                if len(unknown_senders) > 0:
                    print(f"unknown senders: ")
                    for sender in unknown_senders:
                        print(f"{sender}")
                    print("")

        unprioritized_emails = "label:inbox -label:@ReadyToArchive -label:p0 -label:p9 -label:p8 -label:p7 -label:p6 -label:p5 -label:p4 -label:p3 -label:p2 -label:p1 -label:p0 -label:p10 -label:p_unknown"
        thread_ids = self.search_threads(unprioritized_emails, 10000)
        unprioritized_thread_count = len(thread_ids)

        thread_ids = self.search_threads("label:inbox", 10000)
        print(f"{len(thread_ids)} threads in inbox, {unprioritized_thread_count} are unprioritized")

        # threads = set()
        # for email_id in email_ids:
        #     thread_id = self.get_thread_id_from_message_id(email_id)
        #     threads.add(thread_id)
        # print(f"{len(email_ids)} emails in inbox, threads={len(threads)}")

    def date_n_days_ago(self, daysAgo, date_format="%Y/%m/%d"):
        """
        Returns a date string for N days ago in the specified format.

        Args:
            n (int): Number of days ago
            date_format (str): Date format string (default: "%Y-%m-%d")

        Returns:
            str: Formatted date string
        """
        t = timedelta(days=daysAgo)
        target_date = datetime.now() - t
        return target_date.strftime(date_format)

    def count_threads(self):
        queries = ["label:overdue label:P-0_very_high",
                   "label:overdue label:P-1_high",
                   "label:overdue label:P-2_medium",
                   "label:overdue label:P-2_low",
                   "label:TODAY",
                   "label:inbox label:@ReadyToArchive",
                   "label:inbox"]

        print("")
        for query in queries:
            thread_ids = self.search_threads(query, 1000)
            print(f"{len(thread_ids)} \t {query}")
        print("")

    def count_sanelater_threads(self):
        date3DaysAgo = self.date_n_days_ago(3.0)
        query = f"label:@SaneLater is:unread after:{date3DaysAgo}"
        print(f"Running query: {query}")
        thread_ids = self.search_threads(query, 1000)
        print(f"Found {len(thread_ids)} threads")
        total = len(thread_ids)
        fetched_threads = 0
        domain2count = {}

        labeler = GmailLabeler()
        safeDomains = ['airmdr.com']
        labels = labeler.get_labels()
        sanelaterLabelId = labeler.label_id("@SaneLater", labels)


        for id in thread_ids:

            details = self.get_thread_details(id)
            fetched_threads += 1

            fromAddr = self.getSenderFromThreadDetails(details)
            domain = get_domain(fromAddr)
            subject = details['messages'][0]['Subject']

            print(f"From: {fromAddr}")
            print(f"Subject: {subject}")
            choice = input("Enter your choice, enter to mark read, 1 to move to inbox, 2 to skip: ")

            # if safeDomains.__contains__(domain) or choice == 1:
            if choice == "1":
                print(f"Domain {domain} is safe, removing sanelater label and moving to inbox")
                labeler.move_thread_to_inbox(id)
                labeler.remove_label_from_thread(id,sanelaterLabelId, "@SaneLater" )
            if choice == "":
                print("Marking this thread as read..")
                labeler.mark_thread_as_read(id)

            print()

            if domain2count.__contains__(domain):
                domain2count[domain] = domain2count[domain] + 1
            else:
                domain2count[domain] = 1

        sorted_by_count = sorted(domain2count.items(), key=lambda x: -x[1])
        for x in sorted_by_count:
            print(f"{x[1]} \t {x[0]}")

    def getSenderFromThreadDetails(self, details):
        fromAddr = details['messages'][0]['From']
        return fromAddr

    def search_threads(self, query, max_results=10):
        """
        Search for email threads using Gmail search syntax

        Args:
            query: Gmail search query (e.g., "from:example@gmail.com", "subject:invoice")
            max_results: Maximum number of threads to return

        Returns:
            List of thread IDs matching the search
        """
        try:
            results = self.service.users().threads().list(
                userId='me',
                q=query,
                maxResults=max_results
            ).execute()

            threads = results.get('threads', [])
            return [thread['id'] for thread in threads]

        except HttpError as error:
            print(f'An error occurred: {error}')
            return []

    def get_thread_details(self, thread_id):
        """
        Get full details of a specific thread

        Args:
            thread_id: Gmail thread ID

        Returns:
            Dictionary containing thread details
        """
        try:
            thread = self.service.users().threads().get(
                userId='me',
                id=thread_id
            ).execute()

            messages = []
            for message in thread['messages']:
                msg_details = self.parse_message(message)
                messages.append(msg_details)

            return {
                'thread_id': thread_id,
                'message_count': len(messages),
                'messages': messages
            }

        except HttpError as error:
            print(f'An error occurred: {error}')
            return None

    def parse_message(self, message):
        headers = message['payload']['headers']
        fromAddr = ""
        subject  = ""
        for header in headers:
            if header['name'] == "From":
                fromAddr = header["value"]
            if header['name'] == "Subject":
                subject = header["value"]
        return {"Subject": subject, "From":fromAddr}



    def get_thread_id_from_message_id(self, message_id):
        """
        Get thread ID from Gmail message ID

        Args:
            message_id: Gmail message ID (string)

        Returns:
            str: Thread ID
        """
        try:
            # Get message details
            message = self.service.users().messages().get(
                userId='me',
                id=message_id
            ).execute()

            thread_id = message['threadId']

            # print(f"Message ID: {message_id}")
            # print(f"Thread ID: {thread_id}")

            return thread_id

        except HttpError as error:
            print(f"An error occurred: {error}")
            return None

    def label_emails_by_priority(self, priorities, labels):
        unprioritized_emails = "label:inbox -label:@ReadyToArchive -label:p0 -label:p9 -label:p8 -label:p7 -label:p6 -label:p5 -label:p4 -label:p3 -label:p2 -label:p1 -label:p0 -label:p10 -label:p_unknown"
        # Search for emails
        thread_ids = self.search_threads(unprioritized_emails, 10000)
        totalThreads = len(thread_ids)
        threads = 0

        print(f"Found {len(thread_ids)} threads for query: {unprioritized_emails}")
        for thread_id in thread_ids:
            threads += 1
            thread_details = self.get_thread_details(thread_id)
            sender = self.getSenderFromThreadDetails(thread_details)
            name, email = parseaddr(sender)
            priority = self.priority_by_email(priorities, email)
            label_id = self.label_id(priority, labels)
            self.add_label_to_thread(thread_id, label_id)
            print(
                f"{threads}/{totalThreads}: Adding priority label {priority} to sender={sender}, email={email} label_id={label_id}")
            print("")

        # find emails marked unpriroitized that have known priorities and remove the unknown priority label
        unknown_senders_query = "label:p_unknown"
        thread_ids = self.search_threads(unknown_senders_query, 10000)
        print(f"Found {len(thread_ids)} threads with unprioritized senders")
        p_unknown_id = self.label_id("p_unknown", labels)

        unknown_senders = set()
        for thread_id in thread_ids:
            thread_details = self.get_thread_details(thread_id)
            sender = self.getSenderFromThreadDetails(thread_details)
            name, email = parseaddr(sender)
            priority = self.priority_by_email(priorities, email)
            if priority != "p_unknown":
                self.remove_label_from_thread(thread_id, p_unknown_id, "p_unknown")
            else:
                unknown_senders.add(email.lower())

        print("")
        print("Unknown senders:")
        for sender in unknown_senders:
            print(sender)
        print("")


def option_a():
    labeler = GmailLabeler()
    labels = labeler.get_labels()

    downloader = GoogleCSVSheetDownloader.GoogleSheetCSVDownloader()
    downloader.download_sheet_by_url(
        "https://docs.google.com/spreadsheets/d/1JqOnZFU3rghc24LM21wLXfYp3q-JvqDOZOw_GYvgaOg/edit?gid=1339297741",
        "senders2priority", "priorities.csv")
    priorities = csv_to_dict_list("priorities.csv")
    print(f"Read {len(priorities)} rows for senders2priority (Email Senders google sheet)")
    labeler.label_emails_by_priority(priorities, labels)
    labeler.count_by_priority_labels(labels)
    return True


def option_b():
    labeler = GmailLabeler()
    labels = labeler.get_labels()
    labeler.count_by_priority_labels(labels)
    return True

def option_3():
    labeler = GmailLabeler()
    labels = labeler.count_threads()
    return True

def option_4():
    labeler = GmailLabeler()
    labels = labeler.count_sanelater_threads()
    return True

def goodbye():
    print("Goodbye!")
    return False

def main():
    options = {
        '1': ('Label Emails', option_a),
        '2': ('Show Email Stats', option_b),
        '3': ('Show Threads stats', option_3),
        '4': ('Show SaneLater stats', option_4),
        '5': ('Exit', goodbye)
    }

    while True:
        print("\n--- Menu ---")
        for key, (description, _) in options.items():
            print(f"{key}. {description}")

        choice = input("Enter your choice: ")

        if choice in options:
            keepGoing = options[choice][1]()  # Call the function
            if keepGoing == False:
                break
        else:
            print("Invalid choice. Please try again.")

    """Example usage of the Gmail labeler."""
    # Initialize the labeler

    # labeler.remove_priority_labels(labels)


if __name__ == '__main__':
    main()
