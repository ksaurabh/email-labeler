import os
import pickle
import io
import pandas as pd
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseDownload
import requests
import re

# Google Drive API scope for reading files
SCOPES = ['https://www.googleapis.com/auth/drive.readonly']

class GoogleDriveCSVDownloader:
    def __init__(self, credentials_file='credentials.json', token_file='token.pickle'):
        """
        Initialize the Google Drive CSV downloader.
        
        Args:
            credentials_file: Path to the OAuth2 credentials JSON file
            token_file: Path to store the authentication token
        """
        self.credentials_file = credentials_file
        self.token_file = token_file
        self.service = None
        self.authenticate()
    
    def authenticate(self):
        """Authenticate with Google Drive API using OAuth2."""
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
        
        # Build the Drive service
        try:
            self.service = build('drive', 'v3', credentials=creds)
            print("Successfully authenticated with Google Drive API")
        except HttpError as error:
            print(f"An error occurred during authentication: {error}")
            return None
    
    def extract_file_id_from_url(self, url):
        """
        Extract file ID from Google Drive URL.
        
        Args:
            url: Google Drive file URL
            
        Returns:
            File ID or None if not found
        """
        patterns = [
            r'/file/d/([a-zA-Z0-9-_]+)',
            r'id=([a-zA-Z0-9-_]+)',
            r'/d/([a-zA-Z0-9-_]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                return match.group(1)
        
        return None
    
    def get_file_metadata(self, file_id):
        """
        Get metadata for a specific file.
        
        Args:
            file_id: Google Drive file ID
            
        Returns:
            File metadata dictionary
        """
        try:
            file_metadata = self.service.files().get(
                fileId=file_id,
                fields='id,name,mimeType,size,modifiedTime,parents'
            ).execute()
            return file_metadata
        except HttpError as error:
            print(f"An error occurred while getting file metadata: {error}")
            return None
    
    def search_csv_files(self, query=None, max_results=10):
        """
        Search for CSV files in Google Drive.
        
        Args:
            query: Search query (optional)
            max_results: Maximum number of results to return
            
        Returns:
            List of CSV files
        """
        try:
            # Build search query for CSV files
            search_query = "mimeType='text/csv'"
            if query:
                search_query += f" and name contains '{query}'"
            
            results = self.service.files().list(
                q=search_query,
                pageSize=max_results,
                fields="nextPageToken, files(id, name, size, modifiedTime)"
            ).execute()
            
            items = results.get('files', [])
            return items
        except HttpError as error:
            print(f"An error occurred while searching files: {error}")
            return []
    
    def download_csv_by_id(self, file_id, save_path=None):
        """
        Download a CSV file by its file ID.
        
        Args:
            file_id: Google Drive file ID
            save_path: Local path to save the file (optional)
            
        Returns:
            pandas DataFrame or None if failed
        """
        try:
            # Get file metadata
            file_metadata = self.get_file_metadata(file_id)
            if not file_metadata:
                print("Could not retrieve file metadata")
                return None
            
            file_name = file_metadata['name']
            print(f"Downloading: {file_name}")
            
            # Download file content
            request = self.service.files().get_media(fileId=file_id)
            file_content = io.BytesIO()
            downloader = MediaIoBaseDownload(file_content, request)
            
            done = False
            while done is False:
                status, done = downloader.next_chunk()
                if status:
                    print(f"Download progress: {int(status.progress() * 100)}%")
            
            # Reset file pointer
            file_content.seek(0)
            
            # Save to file if path provided
            if save_path:
                with open(save_path, 'wb') as f:
                    f.write(file_content.read())
                print(f"File saved to: {save_path}")
                file_content.seek(0)
            
            # Read as pandas DataFrame
            df = pd.read_csv(file_content)
            print(f"Successfully loaded CSV with {len(df)} rows and {len(df.columns)} columns")
            return df
            
        except HttpError as error:
            print(f"An error occurred while downloading file: {error}")
            return None
        except Exception as error:
            print(f"An error occurred while processing CSV: {error}")
            return None
    
    def download_csv_by_url(self, url, save_path=None):
        """
        Download a CSV file using Google Drive URL.
        
        Args:
            url: Google Drive file URL
            save_path: Local path to save the file (optional)
            
        Returns:
            pandas DataFrame or None if failed
        """
        file_id = self.extract_file_id_from_url(url)
        if not file_id:
            print("Could not extract file ID from URL")
            return None
        
        return self.download_csv_by_id(file_id, save_path)
    
    def download_csv_by_name(self, file_name, save_path=None):
        """
        Download a CSV file by searching for its name.
        
        Args:
            file_name: Name of the CSV file to search for
            save_path: Local path to save the file (optional)
            
        Returns:
            pandas DataFrame or None if failed
        """
        csv_files = self.search_csv_files(query=file_name)
        
        if not csv_files:
            print(f"No CSV files found with name containing: {file_name}")
            return None
        
        # Use the first match
        file_id = csv_files[0]['id']
        print(f"Found file: {csv_files[0]['name']}")
        
        return self.download_csv_by_id(file_id, save_path)
    
    def download_shared_csv(self, share_url, save_path=None):
        """
        Download a CSV file from a shared Google Drive link (no authentication required).
        
        Args:
            share_url: Google Drive sharing URL
            save_path: Local path to save the file (optional)
            
        Returns:
            pandas DataFrame or None if failed
        """
        try:
            # Extract file ID from share URL
            file_id = self.extract_file_id_from_url(share_url)
            if not file_id:
                print("Could not extract file ID from share URL")
                return None
            
            # Create direct download URL
            download_url = f"https://drive.google.com/uc?id={file_id}&export=download"
            
            # Download the file
            response = requests.get(download_url)
            response.raise_for_status()
            
            # Save to file if path provided
            if save_path:
                with open(save_path, 'wb') as f:
                    f.write(response.content)
                print(f"File saved to: {save_path}")
            
            # Read as pandas DataFrame
            df = pd.read_csv(io.StringIO(response.text))
            print(f"Successfully loaded shared CSV with {len(df)} rows and {len(df.columns)} columns")
            return df
            
        except requests.exceptions.RequestException as error:
            print(f"An error occurred while downloading shared file: {error}")
            return None
        except Exception as error:
            print(f"An error occurred while processing shared CSV: {error}")
            return None
    
    def list_csv_files(self, max_results=20):
        """
        List all CSV files in Google Drive.
        
        Args:
            max_results: Maximum number of files to display
            
        Returns:
            List of CSV file information
        """
        csv_files = self.search_csv_files(max_results=max_results)
        
        if not csv_files:
            print("No CSV files found in your Google Drive")
            return []
        
        print(f"Found {len(csv_files)} CSV files:")
        for i, file in enumerate(csv_files, 1):
            size = int(file.get('size', 0)) if file.get('size') else 0
            size_mb = size / (1024 * 1024) if size > 0 else 0
            modified = file.get('modifiedTime', 'Unknown')
            
            print(f"{i}. {file['name']}")
            print(f"   ID: {file['id']}")
            print(f"   Size: {size_mb:.2f} MB")
            print(f"   Modified: {modified}")
            print()
        
        return csv_files

def main():
    """Example usage of the Google Drive CSV downloader."""
    # Initialize the downloader
    downloader = GoogleDriveCSVDownloader()
    
    # Example 1: List all CSV files
    print("=== Listing CSV files in your Google Drive ===")
    csv_files = downloader.list_csv_files(max_results=10)
    
    if csv_files:
        print("\n=== Download Examples ===")
        
        # Example 2: Download by file ID
        print("\n1. Download by File ID:")
        print(f"   df = downloader.download_csv_by_id('{csv_files[0]['id']}')")
        
        # Example 3: Download by file name
        print("\n2. Download by File Name:")
        print(f"   df = downloader.download_csv_by_name('{csv_files[0]['name']}')")
        
        # Example 4: Download by URL
        print("\n3. Download by Google Drive URL:")
        print("   df = downloader.download_csv_by_url('https://drive.google.com/file/d/YOUR_FILE_ID/view')")
        
        # Example 5: Download shared file (no auth required)
        print("\n4. Download Shared File (no authentication):")
        print("   df = downloader.download_shared_csv('https://drive.google.com/file/d/YOUR_FILE_ID/view')")
    
    # Interactive example
    print("\n=== Interactive Download ===")
    choice = input("Enter 'y' to download the first CSV file, or any other key to skip: ")
    
    if choice.lower() == 'y' and csv_files:
        file_to_download = csv_files[0]
        print(f"\nDownloading: {file_to_download['name']}")
        
        # Download and display basic info
        df = downloader.download_csv_by_id(file_to_download['id'])
        
        if df is not None:
            print(f"\nDataFrame Info:")
            print(f"Shape: {df.shape}")
            print(f"Columns: {list(df.columns)}")
            print(f"\nFirst 5 rows:")
            print(df.head())
        else:
            print("Failed to download or process the CSV file")

# Alternative function for downloading shared files without authentication
def download_shared_csv_simple(share_url, save_path=None):
    """
    Simple function to download a shared CSV file without authentication.
    
    Args:
        share_url: Google Drive sharing URL
        save_path: Local path to save the file (optional)
        
    Returns:
        pandas DataFrame or None if failed
    """
    try:
        # Extract file ID from URL
        file_id_match = re.search(r'/file/d/([a-zA-Z0-9-_]+)', share_url)
        if not file_id_match:
            file_id_match = re.search(r'id=([a-zA-Z0-9-_]+)', share_url)
        
        if not file_id_match:
            print("Could not extract file ID from URL")
            return None
        
        file_id = file_id_match.group(1)
        download_url = f"https://drive.google.com/uc?id={file_id}&export=download"
        
        # Download the file
        response = requests.get(download_url)
        response.raise_for_status()
        
        # Save to file if path provided
        if save_path:
            with open(save_path, 'wb') as f:
                f.write(response.content)
            print(f"File saved to: {save_path}")
        
        # Read as pandas DataFrame
        df = pd.read_csv(io.StringIO(response.text))
        print(f"Successfully loaded CSV with {len(df)} rows and {len(df.columns)} columns")
        return df
        
    except Exception as error:
        print(f"An error occurred: {error}")
        return None

if __name__ == '__main__':
    main()
