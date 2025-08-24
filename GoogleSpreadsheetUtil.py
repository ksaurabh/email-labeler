import os
import pickle
import pandas as pd
import requests
import re
import io
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Google Sheets API scope
SCOPES = ['https://www.googleapis.com/auth/spreadsheets']


class GoogleSpreadsheetUtil:
    def __init__(self, credentials_file='credentials.json', token_file='token.pickle'):
        """
        Initialize the Google Sheets CSV downloader.

        Args:
            credentials_file: Path to OAuth2 credentials JSON file
            token_file: Path to store authentication token
        """
        self.credentials_file = credentials_file
        self.token_file = token_file
        self.service = None
        self.authenticate()

    def authenticate(self):
        """Authenticate with Google Sheets API using OAuth2."""
        creds = None

        # Load existing token
        if os.path.exists(self.token_file):
            with open(self.token_file, 'rb') as token:
                creds = pickle.load(token)

        # Get new credentials if needed
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                if not os.path.exists(self.credentials_file):
                    print(f"❌ Error: {self.credentials_file} not found!")
                    print("Please download OAuth2 credentials from Google Cloud Console")
                    return

                flow = InstalledAppFlow.from_client_secrets_file(
                    self.credentials_file, SCOPES)
                creds = flow.run_local_server(port=0)

            # Save credentials
            with open(self.token_file, 'wb') as token:
                pickle.dump(creds, token)

        try:
            self.service = build('sheets', 'v4', credentials=creds)
            print("✅ Successfully authenticated with Google Sheets API")
        except Exception as e:
            print(f"❌ Authentication error: {e}")

    def append_multiple_rows(self, spreadsheet_id, sheet_name, values_array):
        """Append multiple rows of values to a sheet"""
        service = self.service
        try:
            # Prepare the range
            range_name = f'{sheet_name}!A:A'

            body = {
                'values': values_array
            }

            result = service.spreadsheets().values().append(
                spreadsheetId=spreadsheet_id,
                range=range_name,
                valueInputOption='RAW',  # Use 'USER_ENTERED' for formulas
                insertDataOption='INSERT_ROWS',
                body=body
            ).execute()

            rows_added = len(values_array)
            print(f"Appended {rows_added} rows to {sheet_name}")
            return result

        except HttpError as error:
            print(f'An error occurred: {error}')
            return None

    def extract_spreadsheet_id(self, url):
        """
        Extract spreadsheet ID from Google Sheets URL.

        Args:
            url: Google Sheets URL

        Returns:
            Spreadsheet ID or None
        """
        patterns = [
            r'/spreadsheets/d/([a-zA-Z0-9-_]+)',
            r'key=([a-zA-Z0-9-_]+)',
            r'spreadsheets/d/([a-zA-Z0-9-_]+)/'
        ]

        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                return match.group(1)

        return None

    def append_multiple_rows(self, spreadsheet_id, sheet_name, values_array):
        """Append multiple rows of values to a sheet"""
        service = self.service
        try:
            # Prepare the range
            range_name = f'{sheet_name}!A:A'

            body = {
                'values': values_array
            }

            result = service.spreadsheets().values().append(
                spreadsheetId=spreadsheet_id,
                range=range_name,
                valueInputOption='RAW',  # Use 'USER_ENTERED' for formulas
                insertDataOption='INSERT_ROWS',
                body=body
            ).execute()

            rows_added = len(values_array)
            print(f"Appended {rows_added} rows to {sheet_name}")
            return result

        except HttpError as error:
            print(f'An error occurred: {error}')
            return None

    def get_sheet_metadata(self, spreadsheet_id):
        """
        Get metadata for a spreadsheet including all sheet names.

        Args:
            spreadsheet_id: Google Sheets ID

        Returns:
            Dictionary with spreadsheet metadata
        """
        try:
            sheet_metadata = self.service.spreadsheets().get(
                spreadsheetId=spreadsheet_id).execute()

            sheets = sheet_metadata.get('sheets', [])
            sheet_info = []

            for sheet in sheets:
                properties = sheet.get('properties', {})
                sheet_info.append({
                    'title': properties.get('title', 'Unknown'),
                    'sheetId': properties.get('sheetId', 0),
                    'index': properties.get('index', 0),
                    'gridProperties': properties.get('gridProperties', {})
                })

            return {
                'title': sheet_metadata.get('properties', {}).get('title', 'Unknown'),
                'sheets': sheet_info
            }

        except HttpError as e:
            print(f"❌ Error getting sheet metadata: {e}")
            return None

    def download_sheet_as_csv(self, spreadsheet_id, sheet_name=None, save_path=None):
        """
        Download a specific sheet tab as CSV using Google Sheets API.

        Args:
            spreadsheet_id: Google Sheets ID
            sheet_name: Name of the sheet tab (None for first sheet)
            save_path: Local path to save CSV file

        Returns:
            pandas DataFrame or None
        """
        try:
            # Get sheet metadata to find available sheets
            metadata = self.get_sheet_metadata(spreadsheet_id)
            if not metadata:
                return None

            available_sheets = [sheet['title'] for sheet in metadata['sheets']]

            # Determine which sheet to download
            if sheet_name is None:
                sheet_name = available_sheets[0]
                print(f"No sheet specified, using first sheet: '{sheet_name}'")
            elif sheet_name not in available_sheets:
                print(f"❌ Sheet '{sheet_name}' not found!")
                print(f"Available sheets: {available_sheets}")
                return None

            print(f"Downloading sheet: '{sheet_name}'")

            # Get the sheet data
            range_name = f"'{sheet_name}'"  # Use single quotes to handle sheet names with spaces
            result = self.service.spreadsheets().values().get(
                spreadsheetId=spreadsheet_id,
                range=range_name
            ).execute()

            values = result.get('values', [])

            if not values:
                print("❌ No data found in the sheet")
                return None

            # Convert to DataFrame
            # Use first row as headers if it looks like headers
            if len(values) > 1:
                df = pd.DataFrame(values[1:], columns=values[0])
            else:
                df = pd.DataFrame(values)

            print(f"✅ Successfully loaded sheet: {df.shape[0]} rows, {df.shape[1]} columns")

            # Save to file if requested
            if save_path:
                df.to_csv(save_path, index=False)
                print(f"💾 Saved to: {save_path}")

            return df

        except HttpError as e:
            print(f"❌ Error downloading sheet: {e}")
            return None
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            return None

    def download_sheet_by_url(self, url, sheet_name=None, save_path=None):
        """
        Download sheet using Google Sheets URL.

        Args:
            url: Google Sheets URL
            sheet_name: Name of sheet tab
            save_path: Local path to save CSV

        Returns:
            pandas DataFrame or None
        """
        spreadsheet_id = self.extract_spreadsheet_id(url)
        if not spreadsheet_id:
            print("❌ Could not extract spreadsheet ID from URL")
            return None

        return self.download_sheet_as_csv(spreadsheet_id, sheet_name, save_path)

    def list_all_sheets(self, spreadsheet_id):
        """
        List all available sheets in a spreadsheet.

        Args:
            spreadsheet_id: Google Sheets ID

        Returns:
            List of sheet information
        """
        metadata = self.get_sheet_metadata(spreadsheet_id)
        if not metadata:
            return []

        print(f"Spreadsheet: {metadata['title']}")
        print(f"Available sheets ({len(metadata['sheets'])}):")

        for i, sheet in enumerate(metadata['sheets'], 1):
            grid_props = sheet['gridProperties']
            rows = grid_props.get('rowCount', 'Unknown')
            cols = grid_props.get('columnCount', 'Unknown')
            print(f"  {i}. {sheet['title']} ({rows} rows, {cols} columns)")

        return metadata['sheets']


def download_public_sheet_csv(url, sheet_name=None, save_path=None):
    """
    Download CSV from a public Google Sheet without authentication.

    Args:
        url: Google Sheets URL (must be publicly accessible)
        sheet_name: Name of sheet tab (optional)
        save_path: Local path to save CSV file

    Returns:
        pandas DataFrame or None
    """
    try:
        # Extract spreadsheet ID
        spreadsheet_id_match = re.search(r'/spreadsheets/d/([a-zA-Z0-9-_]+)', url)
        if not spreadsheet_id_match:
            print("❌ Could not extract spreadsheet ID from URL")
            return None

        spreadsheet_id = spreadsheet_id_match.group(1)

        # Extract sheet ID or use sheet name
        sheet_id = None
        if '#gid=' in url:
            gid_match = re.search(r'#gid=(\d+)', url)
            if gid_match:
                sheet_id = gid_match.group(1)

        # Build download URL
        if sheet_id:
            # Use sheet ID
            download_url = f"https://docs.google.com/spreadsheets/d/{spreadsheet_id}/export?format=csv&gid={sheet_id}"
        elif sheet_name:
            # Use sheet name (may not work for all cases)
            download_url = f"https://docs.google.com/spreadsheets/d/{spreadsheet_id}/export?format=csv&sheet={sheet_name}"
        else:
            # Default to first sheet
            download_url = f"https://docs.google.com/spreadsheets/d/{spreadsheet_id}/export?format=csv"

        print(f"Downloading from: {download_url}")

        # Download the CSV
        response = requests.get(download_url)
        response.raise_for_status()

        # Check if we got HTML instead of CSV (usually means sheet is private)
        if response.text.strip().startswith('<!DOCTYPE html>'):
            print("❌ Received HTML instead of CSV. The sheet might be private.")
            print("Make sure the sheet is publicly accessible or use authenticated download.")
            return None

        # Read as DataFrame
        df = pd.read_csv(io.StringIO(response.text))
        print(f"✅ Successfully downloaded public sheet: {df.shape[0]} rows, {df.shape[1]} columns")

        # Save to file if requested
        if save_path:
            df.to_csv(save_path, index=False)
            print(f"💾 Saved to: {save_path}")

        return df

    except requests.RequestException as e:
        print(f"❌ Download error: {e}")
        return None
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return None


def get_public_sheet_instructions():
    """Print instructions for making a Google Sheet public."""
    print("""
    To make a Google Sheet publicly accessible:

    1. Open your Google Sheet
    2. Click "Share" button (top right)
    3. Click "Change to anyone with the link"
    4. Set permission to "Viewer"
    5. Copy the link

    The URL should look like:
    https://docs.google.com/spreadsheets/d/SPREADSHEET_ID/edit#gid=SHEET_ID

    To get a specific sheet, you can:
    - Include #gid=SHEET_ID in the URL for a specific tab
    - Or specify the sheet name in the download function
    """)


def main():
    """Example usage and interactive downloader."""
    print("Google Sheets CSV Downloader")
    print("=" * 40)

    print("Choose download method:")
    print("1. Authenticated download (private sheets)")
    print("2. Public sheet download (no authentication)")
    print("3. Show public sheet instructions")

    choice = input("Enter choice (1-3): ").strip()

    if choice == "1":
        # Authenticated download
        downloader = GoogleSpreadsheetUtil.GoogleSpreadsheetUtil()

        if downloader.service is None:
            print("❌ Authentication failed. Cannot proceed.")
            return

        url = input("Enter Google Sheets URL: ").strip()
        if not url:
            return

        spreadsheet_id = downloader.extract_spreadsheet_id(url)
        if not spreadsheet_id:
            print("❌ Invalid Google Sheets URL")
            return

        # List available sheets
        sheets = downloader.list_all_sheets(spreadsheet_id)
        if not sheets:
            return

        # Get sheet selection
        if len(sheets) > 1:
            sheet_choice = input(
                f"\nEnter sheet name or number (1-{len(sheets)}), or press Enter for first sheet: ").strip()

            if sheet_choice.isdigit():
                sheet_index = int(sheet_choice) - 1
                if 0 <= sheet_index < len(sheets):
                    sheet_name = sheets[sheet_index]['title']
                else:
                    print("Invalid sheet number")
                    return
            elif sheet_choice:
                sheet_name = sheet_choice
            else:
                sheet_name = None
        else:
            sheet_name = None

        # Download
        save_choice = input("Save to file? Enter filename (or press Enter to skip): ").strip()
        save_path = save_choice if save_choice else None

        df = downloader.download_sheet_as_csv(spreadsheet_id, sheet_name, save_path)

        if df is not None:
            print(f"\n📊 DataFrame Preview:")
            print(f"Shape: {df.shape}")
            print(f"Columns: {list(df.columns)}")
            print(f"\nFirst 5 rows:")
            print(df.head())

    elif choice == "2":
        # Public download
        url = input("Enter public Google Sheets URL: ").strip()
        if not url:
            return

        sheet_name = input("Enter sheet name (or press Enter for default): ").strip()
        sheet_name = sheet_name if sheet_name else None

        save_choice = input("Save to file? Enter filename (or press Enter to skip): ").strip()
        save_path = save_choice if save_choice else None

        df = download_public_sheet_csv(url, sheet_name, save_path)

        if df is not None:
            print(f"\n📊 DataFrame Preview:")
            print(f"Shape: {df.shape}")
            print(f"Columns: {list(df.columns)}")
            print(f"\nFirst 5 rows:")
            print(df.head())

    elif choice == "3":
        get_public_sheet_instructions()

    else:
        print("Invalid choice")


if __name__ == '__main__':
    main()