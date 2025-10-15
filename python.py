from __future__ import print_function
import os
import hashlib
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# --- Configuration ---
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']
TOKEN_FILE = 'token.json'
CREDENTIALS_FILE = 'credentials.json'

def get_gmail_service():
    """Authenticate and return Gmail service."""
    creds = None
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(TOKEN_FILE, 'w') as token:
            token.write(creds.to_json())
    return build('gmail', 'v1', credentials=creds)

def get_email_hash(message):
    """Generate a hash for deduplication using sender, subject, and snippet."""
    headers = message.get('payload', {}).get('headers', [])
    sender = subject = ''
    for h in headers:
        if h['name'] == 'From':
            sender = h['value']
        if h['name'] == 'Subject':
            subject = h['value']
    snippet = message.get('snippet', '')
    raw_string = (sender + subject + snippet).lower()
    return hashlib.md5(raw_string.encode('utf-8')).hexdigest()

# --- EXTRA CODE STARTS HERE ---
def get_email_details(service, msg_id):
    """Fetch details of an email by ID."""
    msg = service.users().messages().get(
        userId="me",
        id=msg_id,
        format="metadata",
        metadataHeaders=["Subject", "From", "Date"]
    ).execute()

    headers = msg.get("payload", {}).get("headers", [])
    details = {h["name"]: h["value"] for h in headers}
    snippet = msg.get("snippet", "")

    return {
        "id": msg_id,
        "subject": details.get("Subject", "(No Subject)"),
        "sender": details.get("From", "(Unknown Sender)"),
        "date": details.get("Date", "(No Date)"),
        "snippet": snippet
    }

def move_to_trash(service, msg_id):
    """Move a Gmail message to Trash instead of deleting."""
    service.users().messages().trash(userId="me", id=msg_id).execute()
# --- EXTRA CODE ENDS HERE ---

def deduplicate_emails(service, max_emails=200, user_id='me'):
    """Scan and handle duplicate emails (move to Trash after confirmation)."""
    seen = {}
    duplicates = []
    deleted_info = []
    page_token = None
    fetched = 0

    while fetched < max_emails:
        resp = service.users().messages().list(
            userId=user_id,
            maxResults=min(100, max_emails - fetched),
            pageToken=page_token
        ).execute()

        messages = resp.get('messages', [])
        if not messages:
            break

        for msg in messages:
            try:
                message = service.users().messages().get(
                    userId=user_id,
                    id=msg['id'],
                    format='full'
                ).execute()
            except:
                continue

            # Extract headers
            headers = message.get('payload', {}).get('headers', [])
            sender = subject = ''
            for h in headers:
                if h['name'] == 'From':
                    sender = h['value']
                if h['name'] == 'Subject':
                    subject = h['value']
            snippet = message.get('snippet', '')

            key_source = (sender + subject + snippet).lower()
            key = hashlib.md5(key_source.encode('utf-8')).hexdigest()

            if key in seen:
                duplicates.append(msg['id'])
                deleted_info.append({
                    "sender": sender,
                    "subject": subject,
                    "snippet": snippet[:50]  # show first 50 chars
                })
            else:
                seen[key] = msg['id']

            fetched += 1
            if fetched >= max_emails:
                break

        page_token = resp.get('nextPageToken')
        if not page_token:
            break

    # --- EXTRA CODE for showing & moving to Trash ---
    if duplicates:
        print(f"\n⚠️ Found {len(duplicates)} duplicate emails:\n")
        details_list = []
        for msg_id in duplicates:
            details = get_email_details(service, msg_id)
            details_list.append(details)
            print(f"ID: {details['id']}")
            print(f"From: {details['sender']}")
            print(f"Subject: {details['subject']}")
            print(f"Date: {details['date']}")
            print(f"Snippet: {details['snippet']}")
            print("-" * 60)

        # Ask before moving to Trash
        confirm = input("\nDo you want to move these duplicates to Trash? (yes/no): ").lower()
        if confirm == "yes":
            for d in details_list:
                move_to_trash(service, d["id"])
                print(f"Moved to Trash: {d['subject']} ({d['id']})")
        else:
            print("No emails moved to Trash.")
    else:
        print("\nNo duplicates found.")

    print(f"\nUnique emails scanned: {len(seen)}")

if __name__ == '__main__':
    max_scan = int(input("Enter number of emails to scan (max 1000): ") or 200)
    service = get_gmail_service()
    deduplicate_emails(service, max_emails=max_scan)
