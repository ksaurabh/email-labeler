import os
import pickle
import re
import time
import argparse

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from collections import Counter
import GoogleDriveCSVDownloader
import GoogleSpreadsheetUtil
from email.utils import parseaddr
from datetime import datetime, timedelta
import csv
from email.utils import parsedate_tz
from email.utils import formatdate

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
def append_sender_priorities(result, df):
    for row in df.values:
        # print(row)
        result.append({'from': row[0], 'priority':row[1]})


# Gmail API scope for reading and modifying emails
SCOPES = ['https://www.googleapis.com/auth/gmail.modify', 'https://www.googleapis.com/auth/spreadsheets']


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

    def archive_thread(self, thread_id):
        """Archive a specific thread by removing INBOX label"""
        service = self.service
        try:
            # Get all messages in the thread
            thread = service.users().threads().get(
                userId='me', id=thread_id).execute()

            message_ids = [msg['id'] for msg in thread['messages']]

            # Remove INBOX label from all messages in thread (archives them)
            body = {
                'ids': message_ids,
                'removeLabelIds': ['INBOX']
            }

            result = service.users().messages().batchModify(
                userId='me', body=body).execute()

            print(f"Successfully archived thread with {len(message_ids)} messages")
            return True

        except HttpError as error:
            print(f'An error occurred - archive_thread: {error}')
            return False

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
            print(f"An error occurred - move_thread_to_inbox: {error}")
            return False

    def remove_label_from_thread(self, thread_id: str, label_id, label_name, verbose=True,
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

            if verbose:
                print(f"Successfully removed label name={label_name}, id={label_id} from thread {thread_id}")
            return True

        except HttpError as error:
            print(f"An error occurred - remove_label_from_thread: {error}")
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

    def add_label_to_thread(self, thread_id, label_id, label_name, verbose=True):
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

            if verbose:
                if label_name is None:
                    print(f"Successfully added label to thread with {len(message_ids)} messages")
                else:
                    print(f"Successfully added label {label_name} to thread with {len(message_ids)} messages")

            return True

        except HttpError as error:
            print(f'An error occurred - add_label_to_thread: {error}')
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
            print(f"An error occurred - mark_thread_as_read: {error}")
            return False

    def label_id(self, label_name, labels):
        for label in labels:
            if label['name'] == label_name:
                return label['id']
        return label_name

    def label_name(self, label_id, labels):
        for label in labels:
            if label['id'] == label_id:
                return label['name']
        return None

    def remove_priority_labels(self, labels):
        plabels = ["p0", "p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8", "p9", "p10"]
        for plabel in plabels:
            label_id = self.label_id(plabel, labels)
            thread_ids = self.search_threads(f"label:inbox label:{plabel}", 10000)
            print(f"remove_priority_labels: Found {len(thread_ids)} threads with label.name={plabel}", flush=True)
            threads = 0
            totalThreads = len(thread_ids)
            for thread_id in thread_ids:
                self.remove_label_from_thread(thread_id, label_id, plabel)
                threads += 1
                print(f"Updated {threads}/{totalThreads} threads")

    def is_thread_prioritized(self, thread_id):
        labels = self.get_thread_labels_simple(thread_id)
        plabels = set(self.p_cat_labels)
        for label in labels:
            if plabels.__contains__(label):
                return True
        return False

    def get_thread_labels_simple(self, thread_id, user_id='me'):
        """
        Simplified version that returns just label names.

        Args:
            service: Gmail API service object
            thread_id: The ID of the thread
            user_id: Gmail user ID (default: 'me' for authenticated user)

        Returns:
            list: List of label names
        """
        service = self.service
        labels = self.get_labels()
        try:
            thread = service.users().threads().get(
                userId=user_id,
                id=thread_id,
                format='metadata'
            ).execute()

            # Collect all unique label IDs from thread messages
            label_ids = set()
            for message in thread.get('messages', []):
                label_ids.update(message.get('labelIds', []))

            # Get all labels to map IDs to names
            label_names = []
            for id in label_ids:
                label_names.append(self.label_name(id, labels))
                return label_names
        except HttpError as error:
            print(f'An error occurred - get_thread_labels_simple: {error}')
            return []

    plabels = ["p0", "p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8", "p9", "p10", "p_unknown", "@ReadyToArchive"]
    p_cat_labels = ["p_high", "p_medium", "p_low",  "p_unknown", "@ReadyToArchive"]

    def count_by_priority_inbox(self, labels):
        startTime = time.time()
        self.count_by_priority_inbox_untimed(labels)
        timeElapsed = int(time.time() - startTime)
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{now_str}: Time elapsed {timeElapsed} seconds", flush=True)
        print()

    def count_by_priority_inbox_untimed(self, labels):
        plabels = self.p_cat_labels
        total_prioritized_thread_count = 0
        for plabel in plabels:
            label_id = self.label_id(plabel, labels)
            thread_ids = self.search_threads(f"label:inbox label:{plabel}", 10000)
            print(f"count_by_priority_inbox: Found {len(thread_ids)} threads with label.name={plabel}", flush=True)
            total_prioritized_thread_count += len(thread_ids)

        thread_ids = self.search_threads("label:inbox", 10000)
        total_threads = len(thread_ids)
        print(f"{total_threads} threads in inbox, prioritized thread count = {total_prioritized_thread_count}", flush=True)

        unprioritized_threads = self.unprioritized_threads_inbox()

    # def count_by_p_cat_inbox_untimed(self):
    #     labels = self.get_labels()
    #     plabels = [ "p_high", "p_medium", "p_low", "@ReadyForArchive", "p_unknown"]
    #     exclude_queries = []
    #     for plabel in plabels:
    #         label_id = self.label_id(plabel, labels)
    #         thread_ids = self.search_threads(f"label:inbox label:{plabel}", 10000)
    #         print(f"count_by_p_cat_inbox: Found {len(thread_ids)} threads with label.name={plabel}")
    #         exclude_queries.append(f"label:{plabel}")
    #
    #     otherThreads = self.search_threads_w_multiple_exclusions("label:inbox", exclude_queries, 10000)
    #     print(f"Other threads in inbox: {len(otherThreads)}")
    #
    #     # self.label_prioritized_emails_not_in_inbox(labels)

    def label_prioritized_emails_not_in_inbox(self):
        labels = self.get_labels()
        exclude_query = "label:inbox"
        priorityEmailsNotInInbox = "is:unread  after:" + self.date_n_days_ago(14) + f"-({exclude_query})"
        includeQuery = "is:unread  after:" + self.date_n_days_ago(14)
        plabels = ["p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8", "p9", "p10"]
        label_name = "prioritized"
        prioritized_label_id = self.label_id(label_name, labels)
        for plabel in plabels:
            label_id = self.label_id(plabel, labels)
            query = includeQuery + f" label:{plabel}"
            thread_ids = self.search_threads_w_exclusion(query, exclude_query, 10000)
            for thread_id in thread_ids:
                self.add_label_to_thread(thread_id, prioritized_label_id, label_name)
            print(f"Found {len(thread_ids)} threads, query={query}")
        print("Search for these emails using the query: " + priorityEmailsNotInInbox + " label:prioritized")

    def unprioritized_threads_inbox(self, labelUnprioritizedThreads=False):
        unprioritized_inbox_threads_query = "label:inbox -label:@ReadyToArchive -label:p_high -label:p_medium -label:p_low -label:p_unknown"
        excluded_p_cat_queries = self.get_excluded_p_cat_label_queries()

        thread_ids = self.search_threads_w_multiple_exclusions(unprioritized_inbox_threads_query, excluded_p_cat_queries, 10000)
        print()
        print("Running search for unprioritized emails in inbox")
        print(f"query={unprioritized_inbox_threads_query}")
        print(f"search threads returned {len(thread_ids)} threads")
        if labelUnprioritizedThreads:
            print(f"Labeling unprioritized threads...")
            unprioritized_threads = []
            unprioritized_label_id = self.label_id("unprioritized", self.get_labels())
            for thread_id in thread_ids:
                print(".", end="", flush=True)
                if not self.is_thread_prioritized(thread_id):
                    unprioritized_threads.append(thread_id)
                    self.add_label_to_thread(thread_id, unprioritized_label_id, "unprioritized")
            print()
            unprioritized_thread_count = len(unprioritized_threads)
            print(f"unprioritized_thread_count={unprioritized_thread_count}")
            print("You can look for these emails with query: label:inbox label:unprioritized")

    def get_excluded_p_cat_label_queries(self):
        excluded_queries = []
        for plabel in self.p_cat_labels:
            excluded_queries.append("label:" + plabel)
        return excluded_queries

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

            fromAddr = self.get_thread_sender(details)
            domain = get_domain(fromAddr)
            subject = self.get_thread_subject(details)

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

    def get_thread_subject(self, details):
        return details['messages'][0]['Subject']

    def get_thread_sender(self, details):
        fromAddr = details['messages'][0]['From']
        return fromAddr
    def get_thread_max_date_string(self, details):
        max_date_string = details['max_date_string']
        return max_date_string

    def search_threads_w_exclusion(self, include_query, exclude_query, max_results=10):
        included_ids = self.search_threads(include_query, max_results)
        excluded_ids = self.search_threads(exclude_query, max_results)

        result = []
        for id in included_ids:
            if not excluded_ids.__contains__(id):
                result.append(id)
        return result

    def search_threads_w_multiple_exclusions(self, include_query, exclude_queries, max_results=10):
        included_ids = self.search_threads(include_query, max_results)
        excluded_ids = set()
        for exclude_query in exclude_queries:
            ids = self.search_threads(exclude_query, max_results)
            for id in ids:
                excluded_ids.add(id)

        result = []
        for id in included_ids:
            if not excluded_ids.__contains__(id):
                result.append(id)
        return result

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
            print(f'An error occurred - search_threads: {error}')
            return []

    def format_datetime_tuple(self, dt_tuple, format_string="%Y-%m-%d %H:%M:%S"):
        """
        Format a datetime tuple to string

        Args:
            dt_tuple: Tuple in format (year, month, day, hour, minute, second, weekday, yearday, dst)
                     or shorter tuple like (year, month, day, hour, minute, second)
            format_string: strftime format string

        Returns:
            str: Formatted date string
        """
        try:
            # Handle different tuple lengths
            if len(dt_tuple) >= 6:
                dt_obj = datetime(*dt_tuple[:6])
            elif len(dt_tuple) >= 3:
                # Pad with zeros for missing time components
                padded_tuple = dt_tuple + (0,) * (6 - len(dt_tuple))
                dt_obj = datetime(*padded_tuple)
            else:
                raise ValueError("Tuple must have at least year, month, day")

            return dt_obj.strftime(format_string)

        except (TypeError, ValueError) as e:
            return f"Error formatting tuple: {e}"

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
            mostRecentDate = ""
            max_date_string = ''
            for message in thread['messages']:
                msg_details = self.parse_message(message)
                messages.append(msg_details)
                headers = message['payload']['headers']
                date_tuple = None
                date_string = ''
                for header in headers:
                    if header['name'] == 'Date':
                        date_tuple = parsedate_tz(header['value'])
                        date_string = self.format_datetime_tuple(date_tuple, "%Y-%m-%d %H:%M:%S")
                        if date_string > max_date_string:
                            max_date_string = date_string

            return {
                'thread_id': thread_id,
                'message_count': len(messages),
                'messages': messages,
                'max_date_string': max_date_string
            }

        except HttpError as error:
            print(f'An error occurred - get_thread_details: {error}')
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
            print(f"An error occurred - get_thread_id_from_message_id: {error}")
            return None

    def label_emails_by_priority(self, priorities, labels):
        unprioritized_emails = " -label:@ReadyToArchive  -label:p_high -label:p_medium -label:p_low -label:p_unknown"

        print()
        print("Adding priority labels to inbox...")
        excluded_queries = self.get_excluded_p_cat_label_queries()
        unprioritized_emails_inbox = "label:inbox" + unprioritized_emails
        self.add_priority_labels_exclude_prioritized_emails(labels, priorities, unprioritized_emails_inbox, excluded_queries)
        print()

        print("Adding priority labels to unread in last 3d...")
        date3DaysAgo = self.date_n_days_ago(3.0)

        excluded_queries.append("label:inbox")
        unprioritized_emails_unread_3d = f"is:unread after:{date3DaysAgo}" + unprioritized_emails + " label:inbox"
        self.add_priority_labels_exclude_prioritized_emails(labels, priorities,
                                                            unprioritized_emails_unread_3d, excluded_queries)
        print()

    def label_emails_by_priority_category(self, labels):
        # only consider labels that are priority medium, high, very_high
        plabels = ["p2", "p6", "p7", "p8", "p9", "p10"]

        print()
        print("Adding priority category labels to inbox...")
        for plabel in plabels:
            p_cat_label = self.map_label_to_p_cat_label(plabel)

            query = "label:inbox label:" + plabel + " -label:" + p_cat_label
            print()
            thread_ids = self.search_threads(query, max_results=100)
            print(f"Found {len(thread_ids)} threads matching query: " + query, flush=True)

            label_id = self.label_id(p_cat_label, labels)
            print(f"Adding p_cat_label {p_cat_label} to {len(thread_ids)} threads with priority {plabel}", flush=True)
            for thread_id in thread_ids:
                self.add_label_to_thread(thread_id, label_id, p_cat_label)
        print()

        p_cat_labels = ["p_high", "p_medium", "p_low", "unprioritized", "@ReadyToArchive"]
        for label in p_cat_labels:
            query = "label:inbox label:" + label
            thread_ids = self.search_threads(query, 1000)
            print(f"{len(thread_ids)} threads for query: {query}")
        print("", flush=True)

    def map_label_to_p_cat_label(self, plabel):
        if plabel == "p10" or plabel == "p9" :
            p_cat_label = "p_high"
        elif plabel == "p6" or plabel == "p2" or plabel == "p8" or plabel == "p7" or plabel == 'p5':
            p_cat_label = "p_medium"
        else:
            p_cat_label = "p_low"
        return p_cat_label

    # find emails marked unpriroitized that have known priorities and remove the unknown priority label
    def prioritize_last14d_emails_unknown_senders(self, labels, priorities):
        unknown_senders_query = "label:p_unknown after:" + self.date_n_days_ago(14)
        thread_ids = self.search_threads(unknown_senders_query, 10000)
        print(f"Found {len(thread_ids)} threads with unknown senders, query= {unknown_senders_query}")
        p_unknown_id = self.label_id("p_unknown", labels)
        unknown_senders = set()
        for thread_id in thread_ids:
            thread_details = self.get_thread_details(thread_id)
            sender = self.get_thread_sender(thread_details)
            name, email = parseaddr(sender)
            priority = self.priority_by_email(priorities, email)
            if priority != "p_unknown":
                print("Priority changed from unknown to known for: " + email)
                self.remove_label_from_thread(thread_id, p_unknown_id, "p_unknown")
            else:
                unknown_senders.add(email.lower())
            print(".", end="", flush=True)
        print("")

        print(f"Found {len(unknown_senders)} unknown senders")
        if len(unknown_senders) > 0:
            print("Unknown senders:")

            rows = []
            for sender in unknown_senders:
                print(sender)
                rows.append([sender, 0])
            print("")

            sheetsUtil.append_multiple_rows(sheets_id, "ignore-p0", rows)
            print("Finished appending unknown senders to ignore-p0 tab")
            print("sheetsURL: " + sheets_url)
            print()

    def add_priority_labels_exclude_prioritized_emails(self, labels, priorities, unprioritized_emails, excluded_queries):
        # Search for emails
        thread_ids = self.search_threads_w_multiple_exclusions(unprioritized_emails, excluded_queries, 10000)
        # thread_ids = self.search_threads(unprioritized_emails, 10000)
        totalThreads = len(thread_ids)
        threads = 0
        print(f"Found {len(thread_ids)} threads for query: {unprioritized_emails}")
        for thread_id in thread_ids:
            threads += 1
            thread_details = self.get_thread_details(thread_id)
            if thread_details == None:
                continue

            thread_labels = self.get_thread_labels_simple(thread_id)
            sender = self.get_thread_sender(thread_details)
            name, email = parseaddr(sender)

            priority = self.priority_by_email(priorities, email)
            if not thread_labels.__contains__(priority):
                label_id = self.label_id(priority, labels)
                self.add_label_to_thread(thread_id, label_id, priority)
                p_cat_label = self.map_label_to_p_cat_label(priority)
                p_cat_label_id = self.label_id(p_cat_label, labels)
                self.add_label_to_thread(thread_id, p_cat_label_id, p_cat_label)

                date_string = self.get_thread_max_date_string(thread_details)
                print(f"{threads}/{totalThreads}: Adding priority label {priority} to sender={sender}, rcvd={date_string} email={email} labels={thread_labels} label_id={label_id}")
                print("")

def label_emails_w_p_category():
    labeler = GmailLabeler()
    labels = labeler.get_labels()
    labeler.label_emails_by_priority_category(labels)

def continuously_remove_p_category_from_archived_emails():
    labeler = GmailLabeler()
    while True:
        try:
            startTime = time.time()
            remove_p_category_from_archived_emails()
            labeler.count_by_priority_inbox_untimed()
            timeElapsed = int(time.time() - startTime)
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"{now_str}: Time elapssed {timeElapsed} seconds")
            print()
        except:
            pass
        print("sleeping for 3 seconds")
        time.sleep(3)

def remove_p_category_from_archived_emails():
    labeler = GmailLabeler()
    labels = labeler.get_labels()

    print("Removing p_cat_labels from archived emails")
    p_cat_labels = ['p_high', 'p_medium']
    for p_cat_label in p_cat_labels:
        query = f"label:{p_cat_label} -label:inbox"
        thread_ids = labeler.search_threads_w_exclusion(query, "label:inbox", 1000)
        print(f"Found {len(thread_ids)} for query: " + query)
        for thread_id in thread_ids:
            thread_details = labeler.get_thread_details(thread_id)
            sender = labeler.get_thread_sender(thread_details)
            subject = labeler.get_thread_subject(thread_details)


            thread_labels = labeler.get_thread_labels_simple(thread_id)

            isArchived = True
            # print()
            # print(f"Thread Labels: {thread_labels}")
            for label in thread_labels:
                if str(label).lower() == "inbox":
                    isArchived = False
                    break
            # print(f"thread_id: {thread_id} isArchived:{isArchived}")
            if isArchived:
                # print()
                # print(f"{sender} \t {subject} ")
                # print(thread_labels)
                # print(f"Removing label {p_cat_label}")

                label_id = labeler.label_id(p_cat_label, labels)
                labeler.remove_label_from_thread(thread_id, label_id, p_cat_label)
            print(".", end="", flush=True)


def label_emails():
    labeler = GmailLabeler()
    labels = labeler.get_labels()

    priorities = download_sender_priorities()
    print(f"Read {len(priorities)} rows for senders2priority (Email Senders google sheet)")
    labeler.label_emails_by_priority(priorities, labels)
    labeler.label_emails_by_priority_category(labels)
    labeler.count_by_priority_inbox(labels)
    return True

def prioritize_last14d_emails_unknown_senders():
    labeler = GmailLabeler()
    labels = labeler.get_labels()

    priorities = download_sender_priorities()
    print(f"Read {len(priorities)} rows for senders2priority (Email Senders google sheet)")
    labeler.prioritize_last14d_emails_unknown_senders( labels, priorities)
    return True


def download_sender_priorities():
    downloader = GoogleSpreadsheetUtil.GoogleSpreadsheetUtil()
    df1 = downloader.download_sheet_by_url(
        "https://docs.google.com/spreadsheets/d/1JqOnZFU3rghc24LM21wLXfYp3q-JvqDOZOw_GYvgaOg/edit?gid=1339297741",
        "senders2priority")

    df2 = downloader.download_sheet_by_url(
        "https://docs.google.com/spreadsheets/d/1JqOnZFU3rghc24LM21wLXfYp3q-JvqDOZOw_GYvgaOg/edit?gid=1339297741",
        "ignore-p0")

    senders2priority = []
    append_sender_priorities(senders2priority, df1)
    append_sender_priorities(senders2priority, df2)

    # print()
    # print("Senders 2 priority:")
    # for row in senders2priority[0:5]:
    #     print(row)
    # print()
    print("Downloaded sender to priority map from senders2priority tab and ignore-p0 tab")

    return senders2priority

def label_prioritized_emails_not_in_inbox():
    labeler = GmailLabeler()
    labeler.label_prioritized_emails_not_in_inbox()
    return True


def count_by_priority_inbox():
    labeler = GmailLabeler()
    labels = labeler.get_labels()
    labeler.count_by_priority_inbox(labels)
    return True

def option_3():
    labeler = GmailLabeler()
    labels = labeler.count_threads()
    return True

def option_4():
    labeler = GmailLabeler()
    labels = labeler.count_sanelater_threads()
    return True

def timedMethod(method):
    startTime = time.time()
    method()
    timeElapsed = int(time.time() - startTime)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{now_str}: Time elapsed {timeElapsed} seconds")
    print()

def move_low_priority_out_of_inbox():
    labeler = GmailLabeler()
    labels = labeler.get_labels()
    low_p_cat_labels = ['p_low', 'p_unknown', '@ReadyToArchive']
    inboxOverFlowLabel = '@InboxOverflow'
    inboxOverFlowLabelId = labeler.label_id(inboxOverFlowLabel, labels)
    inboxLabel = 'INBOX'
    inboxLabelId = labeler.label_id(inboxLabel, labels)
    for label in low_p_cat_labels:
        label_id = labeler.label_id(label, labels)
        thread_ids = labeler.search_threads(f"label:inbox label:{label}", 1000)
        print(f"Moving {len(thread_ids)} threads matching label:{label} from inbox to inboxOverflow", flush=True)
        for thread_id in thread_ids:
            labeler.add_label_to_thread(thread_id, inboxOverFlowLabelId, inboxOverFlowLabel, False)
            labeler.remove_label_from_thread(thread_id, inboxLabelId, inboxLabel, False)
            print(".", end='', flush=True)
        print("",  flush=True)

def daily_email_routine():
    startTime = time.time()
    label_emails()
    label_prioritized_emails_not_in_inbox()
    label_emails_w_p_category()
    count_by_priority_inbox()
    append_unknown_senders()
    timeElapsed = time.time() - startTime
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{now_str}: Time elapsed {timeElapsed} seconds")
    return True

sheetsUtil = GoogleSpreadsheetUtil.GoogleSpreadsheetUtil()
sheets_url = "https://docs.google.com/spreadsheets/d/1JqOnZFU3rghc24LM21wLXfYp3q-JvqDOZOw_GYvgaOg/edit?gid=1169527381#gid=1169527381"
sheets_id = sheetsUtil.extract_spreadsheet_id(sheets_url)


def calculate_domain_priority():
    df = sheetsUtil.download_sheet_as_csv(sheets_id, "domains")
    rows = df.values.tolist()

    print("Rows in domains tab:")
    for row in rows:
        print(row)
    print()

    domain_priority = dict(rows)

    emailService = GmailLabeler()
    thread_ids = emailService.search_threads("label:inbox")
    new_domains = []
    for thread_id in thread_ids:
        thread_details = emailService.get_thread_details(thread_id)
        unknown_sender = emailService.get_thread_sender(thread_details)
        name, email_addr = parseaddr(unknown_sender)
        domain = re.findall(r'\w+\.\w+$', email_addr)[0]
        if not domain_priority.keys().__contains__(domain):
            new_domains.append([domain])
            print("New domain: " + domain)

    sheetsUtil.append_multiple_rows(sheets_id, "domains", new_domains)
    print(f"Finished appending {len(new_domains)} new domains to the domains tab")
    print("url: " + sheets_url)
    print()

def append_unknown_senders():
    emailService = GmailLabeler()
    unknown_senders = set()
    thread_ids = emailService.search_threads("label:inbox label:p_unknown")
    for thread_id in thread_ids:
        thread_details = emailService.get_thread_details(thread_id)
        unknown_sender = emailService.get_thread_sender(thread_details)
        name, email_addr = parseaddr(unknown_sender)
        unknown_senders.add(email_addr)

    print("")
    print(f"Found {len(unknown_senders)} unknown senders")
    data = []
    for sender in unknown_senders:
        print(sender)
        data.append([sender])
    print("")


    sheet_url = "https://docs.google.com/spreadsheets/d/1JqOnZFU3rghc24LM21wLXfYp3q-JvqDOZOw_GYvgaOg/edit?gid=1304305670#gid=1304305670"
    sheetUtils = GoogleSpreadsheetUtil.GoogleSpreadsheetUtil()
    sheet_id = sheetUtils.extract_spreadsheet_id(sheet_url)
    sheetUtils.append_multiple_rows(sheet_id, "unknown_senders", data)
    print(f"Finished appending unknown senders to {sheet_url}")



def goodbye():
    print("Goodbye!")
    return False

def main():
    parser = argparse.ArgumentParser(description='Email Labeler')
    parser.add_argument('--background', '-b', action='store_true', help='run this in the background')

    args = parser.parse_args()
    print(f"args: {args}")
    print()

    if args.background:
        run_in_bg()
    else:
        run_interactively()

    """Example usage of the Gmail labeler."""
    # Initialize the labeler

    # labeler.remove_priority_labels(labels)

def run_in_bg():
    while True:
        startTime = time.time()
        label_emails()
        move_low_priority_out_of_inbox()
        remove_p_category_from_archived_emails()
        count_by_priority_inbox()

        timeElapsed = int(time.time() - startTime)
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{now_str}: Time elapsed {timeElapsed} seconds")
        print()
        if timeElapsed < 60:
            sleepSeconds = 60 - timeElapsed
            print(f"sleeping for {sleepSeconds} seconds...")
            for i in range(0, sleepSeconds):
                time.sleep(1)
                if i % 10 == 0:
                    print(i, end='', flush=True)
                print(".", end='', flush=True)
        print()

def run_interactively():
    # options_edit_them_here
    options = {
        '1': ('Inbox: Count by Priority', count_by_priority_inbox),
        '2': ('Label Emails', label_emails),
        '3': ('Move p_low, p_unknown and @ReadyToArchive out of inbox', move_low_priority_out_of_inbox),
        '4': ('Show Threads stats', option_3),
        '5': ('Show SaneLater stats', option_4),
        '6': ('Append unknown senders', append_unknown_senders),
        '7': ('Calcualte domain priority', calculate_domain_priority),
        '8': ('Prioritize last14d emails from unknown senders', prioritize_last14d_emails_unknown_senders),
        '9': ('Add priority category labels (assumes threads already have priority labels)', label_emails_w_p_category),
        '10': ('Remove p_cat_labels from archived emails ', remove_p_category_from_archived_emails),
        '11': ('Continuously remove p_cat_labels from archived emails', continuously_remove_p_category_from_archived_emails),
        '12': ('Daily Email Routine', daily_email_routine),
        '13': ('Label Prioritized Emails not in inbox (rcvd in last 14d)', label_prioritized_emails_not_in_inbox),

        # if i reply to an email label it p4 at least.

        '14': ('Exit', goodbye)
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


if __name__ == '__main__':
    main()
