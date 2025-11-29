import json
import os
import pickle
import re
import time
import argparse
import random

from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from collections import Counter
import GoogleDriveCSVDownloader
import GoogleSpreadsheetUtil
import CounterByKey
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
        result.append({'from': row[0], 'priority': row[1]})


# Gmail API scope for reading and modifying emails
SCOPES = ['https://www.googleapis.com/auth/gmail.modify', 'https://www.googleapis.com/auth/spreadsheets', 'https://mail.google.com/']


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
            request = self.service.users().labels().list(userId='me')
            # results = request.execute()
            results = self.execute_with_backoff(request)
            labels = results.get('labels', [])
            return labels
        except HttpError as error:
            print(f"An error occurred while fetching labels: {error}")
            return []

    def execute_with_backoff(self, request):
        backoff = 1
        for i in range(16):  # up to ~64 seconds
            try:
                return request.execute()
            except HttpError as e:
                if e.resp.status == 429:
                    print(e)
                    backoff_sleep = backoff + random.random()
                    print(f"Sleeping to backoff - {backoff_sleep} seconds" )
                    time.sleep(backoff_sleep)
                    backoff *= 2
                    if(backoff > 1800):
                        backoff = 1800
                else:
                    raise
        raise Exception("Max retries exceeded")

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

    def mark_thread_as_read(self, thread_id: str, verbose=True, user_id: str = 'me') -> bool:
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

            if verbose:
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
    def label_id_unsafe(self, label_name, labels):
        for label in labels:
            if label['name'] == label_name:
                return label['id']

        for label in labels:
            if not str(label['name']).startswith("ZD"):
                print(label['name'])

        return None

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
                messageLabelIds = message.get('labelIds', [])
                for messageLabelId in messageLabelIds:
                    label_ids.add(messageLabelId)

            # Get all labels to map IDs to names
            label_names = []
            for id in label_ids:
                label_names.append(self.label_name(id, labels))
            return label_names
        except HttpError as error:
            print(f'An error occurred - get_thread_labels_simple: {error}')
            return []

    plabels = ["p0", "p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8", "p9", "p10", "p_unknown", "@ReadyToArchive"]
    p_cat_labels = ["p_high", "p_medium", "p_low", "p_unknown", "@ReadyToArchive"]

    def count_by_priority_inbox(self, labels):
        startTime = time.time()
        self.count_by_priority_inbox_untimed(labels)
        # template to measure and print timeElapsed
        # startTime = time.time()
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
        print(f"{total_threads} threads in inbox, prioritized thread count = {total_prioritized_thread_count}",
              flush=True)

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

        thread_ids = self.search_threads_w_multiple_exclusions(unprioritized_inbox_threads_query,
                                                               excluded_p_cat_queries, 10000)
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
                labeler.remove_label_from_thread(id, sanelaterLabelId, "@SaneLater")
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
        if not details == None:
            messages = details['messages']
            firstMessage = messages[0]
            fromAddr = firstMessage['From']
            return fromAddr
        else:
            raise Exception("Details is None")

    def get_max_date(self, details):
        return details['max_date_string']

    def get_all_recipients(self, details):
        messages = details['messages']
        receipients = set()
        for message in messages:
            cc = message['Cc']
            peopleOnCC = cc.split(",")
            for p in peopleOnCC:
                name, email = parseaddr(p)
                if email != '' and email.__contains__("@"):
                    receipients.add(email)
            to = message['To']

            people = to.split(",")
            for p in people:
                name, email = parseaddr(p)
                if email != '' and email.__contains__("@"):
                    receipients.add(email)

        return receipients


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
        subject = ""
        cc = ""
        to = ""
        for header in headers:
            if header['name'] == "Cc":
                cc = header["value"]
            if header['name'] == "From":
                fromAddr = header["value"]
            if header['name'] == "Subject":
                subject = header["value"]
            if header['name'] == "To":
                to = header["value"]
        return {"Subject": subject, "From": fromAddr, "Cc": cc, "To": to}


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


    def analyze_sent_emails(self):
        threads = self.search_threads("label:sent", 1000)
        unique_recipients = set()
        for thread in threads:
            thread_details = self.get_thread_details(thread)
            for r in self.get_all_recipients(thread_details):
                if not unique_recipients.__contains__(r):
                    print()
                    print(r, end="", flush=True)
                    unique_recipients.add(r)
                else:
                    print(" .", end="", flush=True)


    def analyze_inbox_overflow_read(self):
        print()
        days = int(input("how many days do you want to scan:"))
        total_unread = 0
        domainCounter = CounterByKey.CounterByKey()
        for i in range(1, days):
            start = self.date_n_days_ago(i)
            end = self.date_n_days_ago(i - 1)
            query = f"label:@inboxoverflow is:unread before:{end} after:{start}"
            threads = self.search_threads(query, 1000)
            print(f"Found {len(threads)} unread threads, query: {query}")
            total_unread += len(threads)
            for thread in threads:
                print(".", end='', flush=True)
                details = self.get_thread_details(thread)
                sender = self.get_thread_sender(details)
                domain = get_domain(sender)
                domainCounter.add(domain)
            print()
        domainCounter.print_by_count()

    def analyze_inbox_overflow_unread(self):
        inboxOverflowLabelName = "@InboxOverflow"
        inboxOverflowLabelID = self.label_id_unsafe(inboxOverflowLabelName, self.get_labels())
        # print(f"inboxOverflowLabelID={inboxOverflowLabelID}")
        # input("Enter any key to continue...")

        self.getIgnoreRules()
        print()
        days = int(input("how many days do you want to scan:"))
        total_unread=0
        for i in range(1, days):
            start = self.date_n_days_ago(i)
            end = self.date_n_days_ago(i-1)
            query = f"label:@inboxoverflow is:unread before:{end} after:{start}"
            threads = self.search_threads(query, 1000)
            print(f"Found {len(threads)} unread threads, query: {query}")
            total_unread += len(threads)
        end = self.date_n_days_ago(days)
        query = f"label:@inboxoverflow is:unread before:{end}"
        threads = self.search_threads(query, 1000)
        total_unread += len(threads)
        print(f"Found {len(threads)} unread threads, query: {query}")
        print(f"Total unread: {total_unread}")
        print()

        query = f"label:@inboxoverflow is:unread  after:{end} -label:inbox"
        threads = self.search_threads(query, 1000)
        print(f"Found {len(threads)} threads, query: {query}")
        labels = self.get_labels()
        ignore_name = "ignore"
        ignore_id = self.label_id(ignore_name, labels)
        left_unread = []
        for thread in threads:
            details = self.get_thread_details(thread)
            subject = self.get_thread_subject(details)
            sender = self.get_thread_sender(details)
            domain = get_domain(sender)
            recipients = self.get_all_recipients(details)
            max_date = self.get_max_date(details)
            message_count = details['message_count']

            ignore = self.safeToIgnore(message_count, recipients, sender, subject)

            info = f"recipients.count={len(recipients)}, max_date:{max_date} from:{ sender} subject:{ subject} recipients: {str(recipients)}"
            infoObj = {
                "subject": subject,
                "sender": sender,
                "domain": domain,
                "recipients": recipients,
                "max_date": max_date,
                "message_count": message_count,
                "thread_id": thread
            }

            if ignore:
                print(f"Marking as read - {info}")
                self.mark_thread_as_read(thread, False)
            else:
                ignore = self.applyIgnoreRules(infoObj)
                if ignore:
                    self.mark_thread_as_read(infoObj['thread_id'])
                else:
                    left_unread.append(infoObj)
                    self.handle_not_safe_to_ignore(infoObj)

                print()

                # else:
                    # input("Add an ignore rule and enter any key to continue...")
                    # ignore = self.applyIgnoreRules(infoObj)
                    # print(f"ignore={ignore}")
                    # if not ignore:
                    #     thread_id = infoObj['thread_id']
                    #     self.move_thread_to_inbox(thread_id)
                    #     self.remove_label_from_thread(thread_id, inboxOverflowLabelID, inboxOverflowLabelName)
                    # input("enter any key to continue...")

        print(f"query={query}")
        print(f"Total threads={len(threads)}, left unread: {len(left_unread)}")
        print()

    def inbox_overflow_skip(self, infoObj):
        print("Skipping...")

    def inbox_overflow_mark_read(self, infoObj):
        self.mark_thread_as_read(infoObj['thread_id'])

    def inbox_overflow_ignore_domain(self, infoObj):
        domain=infoObj['domain']
        ignoreRule = f"domain:{domain}"
        self.append_ignore_rule(ignoreRule)
        self.mark_thread_as_read(infoObj['thread_id'])

    def append_ignore_rule(self, ignoreRule):
        with open('ignoreRules.txt', 'a') as f:
            f.write(ignoreRule)
            f.write("\n")
        print(f"Appended {ignoreRule} to ignoreRules.txt")

    def inbox_overflow_ignore_sender(self, infoObj):
        sender=infoObj['sender']
        email_addr = self.get_email_address_from_sender(sender)
        ignoreRule = f"from:{email_addr}"
        self.append_ignore_rule(ignoreRule)
        self.mark_thread_as_read(infoObj['thread_id'])

    def inbox_overflow_ignore_subject_from_sender(self, infoObj):
        sender=infoObj['sender']
        subject=infoObj['subject']
        email_addr = self.get_email_address_from_sender(sender)
        ignoreRule = f"from:{email_addr} subject:{subject}"
        self.append_ignore_rule(ignoreRule)
        self.mark_thread_as_read(infoObj['thread_id'])

    def inbox_overflow_move_to_inbox(self, infoObj):
        thread_id = infoObj['thread_id']
        self.move_thread_to_inbox(thread_id)

    def ask_to_chose_a_recipient(self, recipients):
        print()
        print("Pick a recipient:")
        index = 0
        for recipient in recipients[:5]:
            index += 1
            print(f"{index}: {recipient}")
        answer = input("Enter your choice: ")
        try:
            return recipients[int(answer)-1]
        except Exception as error:
            print(error)
            print("Not a valid choice, try again.")
            return self.ask_to_chose_a_recipient(recipients)

    def inbox_overflow_recipient(self, infoObj):
        recipients=list(infoObj['recipients'])
        recipient = recipients[0]
        if len(recipients) != 1:
            recipient = self.ask_to_chose_a_recipient(recipients)
        ignoreRule = f"recipients:{recipient} not recipients:kumar@airmdr.com"
        self.append_ignore_rule(ignoreRule)
        self.mark_thread_as_read(infoObj['thread_id'])

    def get_email_address_from_sender(self, sender):
        name, email_addr = parseaddr(sender)
        return email_addr

    def handle_not_safe_to_ignore(self, infoObj):
        options = {
            '1': ('Ignore emails from domain', self.inbox_overflow_ignore_domain),
            '2': ('Ignore emails from sender', self.inbox_overflow_ignore_sender),
            '3': ('Ignore emails w subject from sender', self.inbox_overflow_ignore_subject_from_sender),
            '4': ('Ignore emails to recipient (not me)', self.inbox_overflow_recipient),
            '5': ('Mark as read', self.inbox_overflow_mark_read),
            '6': ('Move to inbox', self.inbox_overflow_move_to_inbox),
            '7': ('Skip', self.inbox_overflow_skip)
        }
        print("\n--- Menu ---")
        for key, (description, _) in options.items():
            print(f"{key}. {description}")

        choice = input("Enter your choice: ")

        if choice in options:
            options[choice][1](infoObj)  # Call the function
        else:
            print("Invalid choice. Please try again.")

    ignoreRules = []
    ignoreRulesLastModifiedTime = 0

    # import re
    # text = "Email: john@example.com, Phone: 123-456-7890"
    # emails = re.findall(r'[\w.-]+@[\w.-]+', text)
    # phones = re.findall(r'\d{3}-\d{3}-\d{4}', text)
    # print(emails, phones)  # ['john@example.com'] ['123-456-7890']
    def applyIgnoreRules(self, infoObject):
        ignoreRules = self.getIgnoreRules()
        for (ruletype, rule, ruletokens) in ignoreRules:
            if ruletype == 1 and str(infoObject['recipients']).__contains__(ruletokens[0]):
                return True
            elif ruletype==2  and str(infoObject['sender']).__contains__(ruletokens[0]) and str(infoObject['subject']).__contains__(ruletokens[1]):
                return True
            elif ruletype==3  and str(infoObject['domain']).__contains__(ruletokens[0]):
                return True
            elif ruletype==4  and str(infoObject['sender']).__contains__(ruletokens[0]) and str(infoObject['recipients']).__contains__(ruletokens[1]) :
                return True
            elif ruletype==5  and str(infoObject['sender']).__contains__(ruletokens[0]):
                return True
            elif ruletype==6  and str(infoObject['subject']).__contains__(ruletokens[0].strip()):
                return True
            # pattern7 = r"\s*recipients:(\S+)\s+not\s+recipients:(\S+)$"
            elif ruletype==7  and str(infoObject['recipients']).__contains__(ruletokens[0].strip()) and not str(infoObject['recipients']).__contains__(ruletokens[1].strip()):
                return True
        self.printEmailInfo(infoObject)
        print(f"No rule match!")
        print()
        return False

    def printEmailInfo(self, infoObject):
        for key in infoObject:
            print(f"{key:20} {infoObject[key]}")

    def parseIgnoreRules(self, rule):
        ignoreRules = self.ignoreRules
        if self.checkRuleMatchAndAppendToIgnoreRules(rule, r"\s*to:(\S+)", 1):
            return True

        pattern2 = r"\s*from:(\S+)\s+subject:(.*)"
        if self.checkRuleMatchAndAppendToIgnoreRules(rule, pattern2, 2):
            return True

        pattern3 = r"\s*domain:(.*)"
        if self.checkRuleMatchAndAppendToIgnoreRules(rule, pattern3, 3):
            return True

        pattern4 = r"\s*from:(\S+)\s+recipients:(\S+)"
        if self.checkRuleMatchAndAppendToIgnoreRules(rule, pattern4, 4):
            return True

        pattern5 = r"\s*from:(\S+)\s*$"
        if self.checkRuleMatchAndAppendToIgnoreRules(rule, pattern5, 5):
            return True

        pattern6 = r"\s*subject:(.*)$"
        if self.checkRuleMatchAndAppendToIgnoreRules(rule, pattern6, 6):
            return True

        pattern7 = r"\s*recipients:(\S+)\s+not\s+recipients:(\S+)$"
        if self.checkRuleMatchAndAppendToIgnoreRules(rule, pattern7, 7):
            return True

        print(f"Rule {rule} did not match any known patterns")
        input("Enter any key to continue..")
        return False

    def checkRuleMatchAndAppendToIgnoreRules(self, rule, pattern1, ruletype):
        matchedRule = False
        match = re.search(pattern1, rule)
        if match != None:
            ruletokens = match.groups()
            if len(ruletokens) > 0:
                self.ignoreRules.append((ruletype, rule, ruletokens))
                matchedRule = True
        return matchedRule

    def getIgnoreRules(self):
        timeToSleep = 300
        # Method 1: Using pathlib (recommended)
        file_path = Path("ignoreRules.txt")
        # print(f"Checking if {file_path} exists..")
        if file_path.exists():
            # Get creation time (or metadata change time on Unix)
            modified_time = file_path.stat().st_mtime
            # print(f"File exists!")
            if self.ignoreRulesLastModifiedTime == None or self.ignoreRulesLastModifiedTime < modified_time:
                self.ignoreRulesLastModifiedTime = modified_time
                # print("It was recently modified..reading it now..")
                with open(file_path, "r") as file:
                    for line in file:
                        if line.strip() != '':
                            # print(line.strip())
                            self.parseIgnoreRules(line.strip())
            # else:
                # print("No change since last read..ignoring it..")
        # else:
        #     print(f"{file_path} does not exist")

        return self.ignoreRules

    def safeToIgnore(self, message_count, recipients, sender, subject):
        ignore = False
        if not recipients.__contains__("kumar@airmdr") and (
                recipients.__contains__("receipts@airmdr.com") or
                recipients.__contains__("mdr-ops@airmdr.com")  or
                recipients.__contains__("data-science@airmdr.com")
        ):
            ignore = True
        elif (
                str(sender).__contains__("do-not-reply@gong.io") or
                str(sender).__contains__("hello@mercury.com") or
                str(sender).__contains__("assistant@avoma.com")
        ):
            ignore = True
        elif (
                str(sender).__contains__("no-reply@airmdr.com") and len(recipients) == 1 and recipients.__contains__("support@airmdr.com")
        ):
            ignore = True
        elif (
                subject.startswith("Updated invitation")
                or subject.startswith("Re: Invitation:")
                or subject.startswith("Tentatively Accepted:")
                or subject.startswith("Invitation")
                or subject.startswith("Declined:")
                or subject.startswith("AI Usage Report")
                or subject.startswith("[JIRA]")
                or subject.startswith("Your daily Gong:")
        ):
            ignore = True
        elif sender == "suyash@airmdr.com" and subject.startswith("AI Usage Report"):
            ignore = True
        elif len(recipients) == 1 and recipients.__contains__("mdr-ops@airmdr.com"):
            ignore = True
        elif len(recipients) == 1 and recipients.__contains__("kumar@airmdr.com") and str(sender).__contains__(
                "no-reply@zoom.us"):
            ignore = True
        elif len(recipients) == 2 and recipients.__contains__("mdr-ops@airmdr.com") and recipients.__contains__(
                "anthony@airmdr.com"):
            ignore = True
        ignore_sender_subjects = [
            ("data-science@airmdr.com", "Your OpenAI API account has been funded"),
            ("suyash@airmdr.com", "AWS Cost Report for AWS & GCP - Last 1d")
        ]
        for p in ignore_sender_subjects:
            sender1, subject1 = p
            if not ignore and self.ignore_sender_subject(sender1, subject1, sender, subject):
                ignore = True
        if not ignore and recipients.__contains__("Receipts@airmdr.com") and not recipients.__contains__("kumar@airmdr.com"):
            ignore = True
        if not ignore and message_count == 1 and (
                str(subject).startswith("Accepted")
                or str(subject).__contains__("card has been charged")
                or str(subject).__contains__("High Priority Bugs Open for too long")
                or str(subject).__contains__("Execution failure alert")
        ):
            ignore = True
        return ignore

    def ignore_sender_subject(self, sender1, subject1, sender, subject):
        return str(sender).__contains__(
            sender1) and subject == subject1

    def label_emails_by_priority(self, priorities, labels, subject_low, domain_high):
        unprioritized_emails = " -label:@ReadyToArchive  -label:p_high -label:p_medium -label:p_low -label:p_unknown"

        print()
        print("Adding priority labels to inbox...")
        excluded_queries = self.get_excluded_p_cat_label_queries()
        unprioritized_emails_inbox = "label:inbox" + unprioritized_emails
        self.add_priority_labels_exclude_prioritized_emails(labels, priorities,
                                                            unprioritized_emails_inbox, excluded_queries, subject_low,
                                                            domain_high)
        print()

        # print("Adding priority labels to unread in last 3d...")
        # date3DaysAgo = self.date_n_days_ago(3.0)
        #
        # excluded_queries.append("label:inbox")
        # unprioritized_emails_unread_3d = f"is:unread after:{date3DaysAgo}" + unprioritized_emails + " label:inbox"
        # self.add_priority_labels_exclude_prioritized_emails(labels, priorities,
        #                                                     unprioritized_emails_unread_3d,
        #                                                     excluded_queries, subject_low, domain_high)
        # print()


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

        p_cat_labels = ["p_high", "p_low", "unprioritized", "@ReadyToArchive"]
        for label in p_cat_labels:
            query = "label:inbox label:" + label
            thread_ids = self.search_threads(query, 1000)
            print(f"{len(thread_ids)} threads for query: {query}")
        print("", flush=True)


    def map_label_to_p_cat_label(self, plabel):
        if plabel == "p10" or plabel == "p9" or plabel == "p6" or plabel == "p2" or plabel == "p8" or plabel == "p7" or plabel == 'p5':
            p_cat_label = "p_high"
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


    def add_priority_labels_exclude_prioritized_emails(self, labels, priorities,
                                                       unprioritized_emails, excluded_queries, subject_low,
                                                       domain_high):
        # Search for emails
        thread_ids = self.search_threads_w_multiple_exclusions(unprioritized_emails, excluded_queries, 10000)
        # thread_ids = self.search_threads(unprioritized_emails, 10000)
        threads = 0
        print(f"Found {len(thread_ids)} threads for query: {unprioritized_emails}, exlcudedQueries={excluded_queries}")

        for thread_id in thread_ids:
            threads += 1
            thread_details = self.get_thread_details(thread_id)
            if thread_details == None:
                continue

            print(f"Adding label to thread {threads}/{len(thread_ids)}")
            self.add_priority_label_to_thread(domain_high, labels, priorities, subject_low, thread_details, thread_id)

        # marked unread high /medium priority emails with unread_high_medium
        self.label_unread(labels, "p_medium")
        self.label_unread(labels, "p_high")
        print("Done marking unread_high_medium")
        print()
    def print_unprioritized_emails(self):
        unprioritized_emails = " -label:@ReadyToArchive  -label:p_high -label:p_medium -label:p_low -label:p_unknown"

        print()
        print("Print unprioritized emails in inbox...")
        excluded_queries = self.get_excluded_p_cat_label_queries()
        unprioritized_emails_inbox = "label:inbox" + unprioritized_emails

        # Search for emails
        thread_ids = self.search_threads_w_multiple_exclusions(unprioritized_emails_inbox, excluded_queries, 10000)
        # thread_ids = self.search_threads(unprioritized_emails, 10000)
        totalThreads = len(thread_ids)
        threads = 0
        print(f"Found {len(thread_ids)} threads for query: {unprioritized_emails_inbox}, exlcudedQueries={excluded_queries}")
        for thread_id in thread_ids:
            threads += 1
            thread_details = self.get_thread_details(thread_id)
            if thread_details == None:
                continue

            sender = self.get_thread_sender(thread_details)
            subject = self.get_thread_subject(thread_details)
            thread_labels = self.get_thread_labels_simple(thread_id)
            print(f"from:{sender} \t subject={subject}, thread_labels={thread_labels}")
        print()

    def add_priority_label_to_thread(self, domain_high, labels, priorities, subject_low, thread_details, thread_id):
        thread_labels = self.get_thread_labels_simple(thread_id)
        sender = self.get_thread_sender(thread_details)
        name, email = parseaddr(sender)
        subject = self.get_thread_subject(thread_details)
        domain = getDomainFromEmailAddress(email)
        date_string = self.get_thread_max_date_string(thread_details)
        if subject_low.__contains__((email, subject)):
            label_id = self.label_id("p_low", labels)
            self.add_label_to_thread(thread_id, label_id, "p_low")
            print(f"Marking thread as low priority based on subject={subject}, from={email}")
        elif domain_high.__contains__(domain):
            label_id = self.label_id("p_high", labels)
            self.add_label_to_thread(thread_id, label_id, "p_high")
            label_id = self.label_id("p9", labels)
            self.add_label_to_thread(thread_id, label_id, "p9")
            print(f"Marking thread as high priority based on domain {domain}")
        else:
            print(f"Not a low priority subject, or high domain (domain={domain}, subject={subject}, from={email}")
            print(f"thread_labels={thread_labels}")
            priority = self.priority_by_email(priorities, email)
            if not thread_labels.__contains__(priority):
                label_id = self.label_id(priority, labels)
                self.add_label_to_thread(thread_id, label_id, priority)
                print(f"Adding priority label {priority} to sender={sender}, rcvd={date_string} email={email} labels={thread_labels} label_id={label_id}")
            p_cat_label = self.map_label_to_p_cat_label(priority)
            if not thread_labels.__contains__(p_cat_label):
                p_cat_label_id = self.label_id(p_cat_label, labels)
                self.add_label_to_thread(thread_id, p_cat_label_id, p_cat_label)
                print(f"Adding p_cat_label: {p_cat_label}  to sender={sender}, rcvd={date_string} email={email} labels={thread_labels} p_cat_label_id={p_cat_label_id}")

        print("")

    def label_unread(self, labels, priority_label):
        query = f"is:unread label:inbox label:{priority_label} -label:unread_high_medium"
        excluded_query = "label:unread_high_medium label:inbox"
        thread_ids = self.search_threads_w_exclusion(query, excluded_query, 1000)
        for thread_id in thread_ids:
            label = "unread_high_medium"
            label_id = self.label_id(label, labels)
            self.add_label_to_thread(thread_id, label_id, label)


def label_emails_w_p_category():
    labeler = GmailLabeler()
    labels = labeler.get_labels()
    labeler.label_emails_by_priority_category(labels)


def continuously_remove_p_category_from_archived_emails():
    labeler = GmailLabeler()
    while True:
        try:
            startTime = time.time()
            remove_stale_p_labels()
            labeler.count_by_priority_inbox_untimed()
            timeElapsed = int(time.time() - startTime)
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"{now_str}: Time elapssed {timeElapsed} seconds")
            print()
        except:
            pass
        print("sleeping for 3 seconds")
        time.sleep(3)


def remove_unread_high_medium():
    labeler = GmailLabeler()
    labels = labeler.get_labels()


def remove_stale_p_labels():
    startTime = time.time()

    labeler = GmailLabeler()
    labels = labeler.get_labels()
    unread_label = "unread_high_medium"
    unread_label_id = labeler.label_id(unread_label, labels)

    query = f"label:unread_high_medium"
    thread_ids = labeler.search_threads(query,  1000)
    print(f"Found {len(thread_ids)} for query: " + query)
    unread = 0
    read = 0
    for thread_id in thread_ids:
        # check if all messages in the thread are read.
        details = labeler.get_thread_details(thread_id)
        subject = labeler.get_thread_subject(details)
        sender = labeler.get_thread_sender(details)
        thread_labels = labeler.get_thread_labels_simple(thread_id)

        isUnread = thread_labels.__contains__("UNREAD")
        if isUnread:
            print(".", end='', flush=True)
            # print(f"sender:{sender}")
            # print(f"subject:{subject}")
            # print(f"isUnread: {isUnread}")
            # print(f"labels:{thread_labels}")
            # print()
            unread += 1
        else:
            print()
            print(f"isUnread: {isUnread} \t subject:{subject}")
            labeler.remove_label_from_thread(thread_id, unread_label_id, unread_label)
            print(f" Removing {unread_label} from this thread")
            read += 1
    print(f"read: {read}, unread: {unread}")
    print()

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
        timeElapsed = int(time.time() - startTime)
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{now_str}: Time elapsed {timeElapsed} seconds")
        print()


def label_emails():
    labeler = GmailLabeler()
    labels = labeler.get_labels()

    priorities = download_sender_priorities()
    print(f"Read {len(priorities)} rows for senders2priority (Email Senders google sheet)")

    update_email_hints()

    labeler.label_emails_by_priority(priorities, labels, subject_low, domain_high)
    labeler.label_emails_by_priority_category(labels)
    labeler.count_by_priority_inbox(labels)
    return True

def print_unprioritized_emails():
    labeler = GmailLabeler()
    labeler.print_unprioritized_emails()

def label_thread_by_query():
    query = input("Enter search query: ")
    print(f"Fetching (at most 10) threads that matches this query: {query}")


    labeler = GmailLabeler()
    threads = labeler.search_threads(query, 10)
    print(f"Found {len(threads)} threads")
    labels = labeler.get_labels()

    priorities = download_sender_priorities()
    print(f"Read {len(priorities)} rows for senders2priority (Email Senders google sheet)")
    update_email_hints()
    print()

    for thread_id in threads:
        thread_details = labeler.get_thread_details(thread_id)
        if thread_details != None:
            labeler.add_priority_label_to_thread(domain_high, labels, priorities, subject_low, thread_details, thread_id)
            move_low_priority_out_of_inbox_v2(labeler, labels, [thread_id])
        else:
            print("Could not find thread details")



def prioritize_last14d_emails_unknown_senders():
    labeler = GmailLabeler()
    labels = labeler.get_labels()

    priorities = download_sender_priorities()
    print(f"Read {len(priorities)} rows for senders2priority (Email Senders google sheet)")
    labeler.prioritize_last14d_emails_unknown_senders(labels, priorities)
    return True


def download_sender_priorities():
    downloader = GoogleSpreadsheetUtil.GoogleSpreadsheetUtil()
    df1 = downloader.download_sheet_by_url(
        "https://docs.google.com/spreadsheets/d/1JqOnZFU3rghc24LM21wLXfYp3q-JvqDOZOw_GYvgaOg/edit?gid=1339297741",
        "senders2priority", "senders2.priority.csv")

    df2 = downloader.download_sheet_by_url(
        "https://docs.google.com/spreadsheets/d/1JqOnZFU3rghc24LM21wLXfYp3q-JvqDOZOw_GYvgaOg/edit?gid=1339297741",
        "ignore-p0", "ignore-p0.csv")

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
    startTime = time.time()
    labeler = GmailLabeler()
    labels = labeler.get_labels()
    move_low_priority_out_of_inbox_v2(labeler, labels)

    timeElapsed = int(time.time() - startTime)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{now_str}: Move low priority emails out of inbox - Time elapsed {timeElapsed} seconds", flush=True)
    print()

def move_low_priority_out_of_inbox_fast_timed():
    startTime = time.time()
    labeler = GmailLabeler()
    labels = labeler.get_labels()
    move_low_priority_out_of_inbox_fast(labeler, labels)

    timeElapsed = int(time.time() - startTime)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{now_str}: Move low priority emails out of inbox (fast) - Time elapsed {timeElapsed} seconds", flush=True)
    print()


lastTimeMovedLowPriorityEmailsOutOfInbox = 0
timeBetweenMovingLowPriorityEmailsOutOfInbox = 300

def move_low_priority_out_of_inbox_v2(labeler, labels, includeOnlyThreadIds=None):
    global lastTimeMovedLowPriorityEmailsOutOfInbox
    global timeBetweenMovingLowPriorityEmailsOutOfInbox
    if lastTimeMovedLowPriorityEmailsOutOfInbox > time.time() - timeBetweenMovingLowPriorityEmailsOutOfInbox:
        print(f"Skipping moving low priority emails out of inbox..." +
              f"not enough time has elapsed - {time.time() - lastTimeMovedLowPriorityEmailsOutOfInbox} seconds")
        return
    lastTimeMovedLowPriorityEmailsOutOfInbox = time.time()
    low_p_cat_labels = ['@ReadyToArchive']
    inboxOverFlowLabel = '@InboxOverflow'
    inboxOverFlowLabelId = labeler.label_id(inboxOverFlowLabel, labels)
    inboxLabel = 'INBOX'
    inboxLabelId = labeler.label_id(inboxLabel, labels)
    print()
    print("Moving low priority emails out of inbox...")
    print("Fetching labels for emails in inbox")
    # id2Labels = fetchLabelsForEmailsInInbox(labeler)
    id2Labels = time_function(fetchLabelsForEmailsInInbox, labeler)
    for label in low_p_cat_labels:
        label_id = labeler.label_id(label, labels)
        thread_ids = searchInboxForEmailsWithLabel(label, labeler, id2Labels)
        print()
        print(f"Moving {len(thread_ids)} threads matching label:{label} from inbox to inboxOverflow", flush=True)
        if(includeOnlyThreadIds != None):
            for id in includeOnlyThreadIds:
                foundInSearch = thread_ids.__contains__(id)
                print(f"Found {id} in search results, would have moved it")
        else:
            for thread_id in thread_ids:
                labeler.add_label_to_thread(thread_id, inboxOverFlowLabelId, inboxOverFlowLabel, False)
                labeler.remove_label_from_thread(thread_id, inboxLabelId, inboxLabel, False)
                print(".", end='', flush=True)
            print("", flush=True)

def move_low_priority_out_of_inbox_fast(labeler, labels, includeOnlyThreadIds=None):
    low_p_cat_labels = ['@ReadyToArchive']
    inboxOverFlowLabel = '@InboxOverflow'
    inboxOverFlowLabelId = labeler.label_id(inboxOverFlowLabel, labels)
    inboxLabel = 'INBOX'
    inboxLabelId = labeler.label_id(inboxLabel, labels)
    print()
    print("Moving low priority emails out of inbox... (fast version)")
    for label in low_p_cat_labels:
        thread_ids = searchInboxForEmailsWithLabel_fast(label, labeler)
        print()
        print(f"Moving {len(thread_ids)} threads matching label:{label} from inbox to inboxOverflow", flush=True)
        if(includeOnlyThreadIds != None):
            for id in includeOnlyThreadIds:
                foundInSearch = thread_ids.__contains__(id)
                print(f"Found {id} in search results, would have moved it")
        else:
            for thread_id in thread_ids:
                labeler.add_label_to_thread(thread_id, inboxOverFlowLabelId, inboxOverFlowLabel, False)
                labeler.remove_label_from_thread(thread_id, inboxLabelId, inboxLabel, False)
                print(".", end='', flush=True)
            print("", flush=True)


def searchInboxForEmailsWithLabel(label, labeler, mapId2Labels):
    thread_ids = labeler.search_threads(f"label:inbox", 1000)
    print(f"Found {len(thread_ids)} emails in inbox")
    result =[]
    for id in thread_ids:
        print(".", end='', flush=True)
        labels = get_cached_labels(id, mapId2Labels, labeler)
        for email_label in labels:
            if label.lower() == email_label.lower():
                result.append(id)
    return result
def searchInboxForEmailsWithLabel_fast(label, labeler):
    query = f"label:inbox label:{label}"
    print(f"Searching inbox query={query}")
    return labeler.search_threads(query, 1000)


def get_cached_labels(id, mapId2Labels, labeler):
    if mapId2Labels.__contains__(id):
        labels = mapId2Labels[id]
    else:
        labels = labeler.get_thread_labels_simple(id)
        mapId2Labels[id] = labels
    return labels


def fetchLabelsForEmailsInInbox(labeler):
    thread_ids = labeler.search_threads(f"label:inbox", 1000)
    print()
    print(f"Found {len(thread_ids)} emails in inbox")
    result = dict()
    for id in thread_ids:
        print(".", end='', flush=True)
        labels = labeler.get_thread_labels_simple(id)
        result[id] = labels
    return result


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


def time_function(func, *args, **kwargs):
    """
    Execute a function and print how long it took to run.

    Args:
        func: The function to time
        *args: Positional arguments to pass to func
        **kwargs: Keyword arguments to pass to func

    Returns:
        The result of the function call
    """
    start_time = time.time()
    result = func(*args, **kwargs)
    end_time = time.time()

    elapsed_time = end_time - start_time
    print(f"Function '{func.__name__}' took {elapsed_time:.6f} seconds to run")

    return result


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


# hints to prioritize
subject_low = set()
domain_high = set()
hints_fetch_time = 0
update_frequency_in_seconds = 60


def analyze_sent_emails():
    emailService = GmailLabeler()
    emailService.analyze_sent_emails()

def analyze_inbox_overflow_unread():
    emailService = GmailLabeler()
    emailService.analyze_inbox_overflow_unread()

def analyze_inbox_overflow_read():
    emailService = GmailLabeler()
    emailService.analyze_inbox_overflow_read()


def update_email_hints():
    global hints_fetch_time
    global subject_low
    global domain_high
    if (time.time() < hints_fetch_time + update_frequency_in_seconds):
        tryagainAfter = (hints_fetch_time + update_frequency_in_seconds - time.time()).__int__()
        print(f"Skipping fetching hints (e.g. low priority subjects, high priority domains)")
        print(f"We only fetch once every {update_frequency_in_seconds} seconds), try after {tryagainAfter} seconds")
    else:
        emailService = GmailLabeler()
        update_subject_low(emailService)
        update_domain_high(emailService)
        hints_fetch_time = time.time()


def update_subject_low(emailService):
    global subject_low
    subject_low = set()
    thread_ids = emailService.search_threads("label:subject_low")
    for thread_id in thread_ids:
        thread_details = emailService.get_thread_details(thread_id)
        sender = emailService.get_thread_sender(thread_details)
        name, email_addr = parseaddr(sender)
        subject = emailService.get_thread_subject(thread_details)
        subject_low.add((email_addr, subject))
    print("From/subject with priority low:")
    for x in subject_low:
        print(x)
    print()


def update_domain_high(emailService):
    global domain_high
    domain_high = set()
    thread_ids = emailService.search_threads("label:domain_high")
    for thread_id in thread_ids:
        thread_details = emailService.get_thread_details(thread_id)
        if thread_details != None:
            sender = emailService.get_thread_sender(thread_details)
            name, email_addr = parseaddr(sender)
            domain = getDomainFromEmailAddress(email_addr)
            domain_high.add(domain)
        else:
            print(f"Could not find details for thread with thread_id: {thread_id}")
    print("Domains with high priority:")
    for x in domain_high:
        print(x)
    print()


def getDomainFromEmailAddress(email_addr):
    tokens = email_addr.split(".")
    l = len(tokens)
    if l >= 2:
        domain = tokens[l - 2] + "." + tokens[l - 1]
    else:
        domain = email_addr
    return domain


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
    labeler = GmailLabeler()

    # labeler.remove_priority_labels(labels)


def run_in_bg():
    timeToSleep = getTimeToSleep()
    while True:
        timeElapsed = one_background_loop()
        timeToSleep = getTimeToSleep()

        print(f"Time to sleep = {timeToSleep}")

        if timeElapsed < timeToSleep:
            sleepSeconds = timeToSleep - timeElapsed
            print(f"sleeping for {sleepSeconds} seconds...")
            for i in range(0, sleepSeconds):
                time.sleep(1)
                if i % 10 == 0:
                    print(i, end='', flush=True)
                print(".", end='', flush=True)
        print()


def one_background_loop():
    startTime = time.time()
    label_emails()
    move_low_priority_out_of_inbox()
    remove_stale_p_labels()
    count_by_priority_inbox()
    timeElapsed = int(time.time() - startTime)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{now_str}: Time elapsed {timeElapsed} seconds")
    print()
    return timeElapsed


def getTimeToSleep():
    timeToSleep = 300
    # Method 1: Using pathlib (recommended)
    file_path = Path("timeToSleep.txt")
    print(f"Checking if {file_path} exists..")
    if file_path.exists():
        # Get creation time (or metadata change time on Unix)
        modified_time = file_path.stat().st_mtime
        creation_datetime = datetime.fromtimestamp(modified_time)

        # Calculate how long ago
        time_ago = datetime.now() - creation_datetime

        print(f"File exists!")
        print(f"Created: {creation_datetime}")
        print(f"Created {time_ago.days} days and {time_ago.seconds // 3600} hours ago")

        if time_ago.seconds < 3600:
            with open(file_path, "r") as file:
                first_line = file.readline()
                print(first_line)
                timeToSleep = int(first_line)
        else:
            print("Time to sleep file was modified more than an hour ago, ignoring it")
    else:
        print("File does not exist")
    return timeToSleep


def run_interactively():
    # edit options here
    options = {
        '1': ('Inbox: Count by Priority', count_by_priority_inbox),
        '2': ('Label Emails', label_emails),
        '3': ('Move @ReadyToArchive out of inbox (fast)', move_low_priority_out_of_inbox_fast_timed),
        '3b': ('Move p_low, p_unknown and @ReadyToArchive out of inbox (full)', move_low_priority_out_of_inbox),
        '4': ('Show Threads stats', option_3),
        '5': ('Show SaneLater stats', option_4),
        '6': ('Append unknown senders', append_unknown_senders),
        '7': ('Calcualte domain priority', calculate_domain_priority),
        '8': ('Prioritize last14d emails from unknown senders', prioritize_last14d_emails_unknown_senders),
        '9': ('Add priority category labels (assumes threads already have priority labels)', label_emails_w_p_category),
        '10': ('Remove stale priority labels: p_cat_labels from archived emails, unread_high_medium from read ',
               remove_stale_p_labels),
        '11': (
        'Continuously remove p_cat_labels from archived emails', continuously_remove_p_category_from_archived_emails),
        '12': ('Daily Email Routine', daily_email_routine),
        '13': ('Label Prioritized Emails not in inbox (rcvd in last 14d)', label_prioritized_emails_not_in_inbox),
        '14': ('Deprioritize emails with low priority subjects', update_email_hints),
        '15': ('analyze sent emails', analyze_sent_emails),
        '16': ('analyze inbox overflow unread', analyze_inbox_overflow_unread),
        '17': ('analyze inbox overflow read', analyze_inbox_overflow_read),
        '18': ('Label threads matching a query', label_thread_by_query),
        '19': ('Print unprioritized emails', print_unprioritized_emails),
        '20': ('One background loop', one_background_loop),

        # if i reply to an email label it p4 at least.

        '21': ('Exit', goodbye)
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
