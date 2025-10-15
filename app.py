import os
import hashlib
from flask import Flask, session, redirect, url_for, request, render_template, flash
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build


# --- Configuration ---
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # allow http for local dev
APP_SECRET_KEY = "replace-with-a-random-secret"  # change before deploy
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
CLIENT_SECRETS_FILE = "client_secrets.json"
OAUTH2_CALLBACK = os.environ.get("OAUTH2_CALLBACK", "http://localhost:5000/oauth2callback")

app = Flask(__name__)
app.secret_key = APP_SECRET_KEY

# --- Helpers ---
def creds_to_dict(creds: Credentials):
    return {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scopes": creds.scopes,
    }

def creds_from_session():
    if "credentials" not in session:
        return None
    return Credentials(**session["credentials"])

# --- Routes ---
@app.route("/")
def index():
    creds = creds_from_session()
    signed_in = creds is not None and creds.valid
    return render_template("index.html", signed_in=signed_in)

@app.route("/authorize")
def authorize():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=OAUTH2_CALLBACK,
    )
    authorization_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent"
    )
    session["state"] = state
    return redirect(authorization_url)

@app.route("/oauth2callback")
def oauth2callback():
    state = session.get("state", None)
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=state,
        redirect_uri=OAUTH2_CALLBACK,
    )
    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials
    session["credentials"] = creds_to_dict(creds)
    return redirect(url_for("index"))

@app.route("/signout")
def signout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/dedupe", methods=["POST"])
def dedupe():
    creds = creds_from_session()
    if not creds or not creds.valid:
        return redirect(url_for("index"))

    service = build("gmail", "v1", credentials=creds)
    user_id = "me"

    # Get number of emails to scan from the form
    max_emails = int(request.form.get("max_emails", 100))

    seen = {}
    duplicates = []
    page_token = None
    fetched_emails = 0

    while fetched_emails < max_emails:
        resp = service.users().messages().list(
            userId=user_id,
            maxResults=min(100, max_emails - fetched_emails),
            pageToken=page_token
        ).execute()
        messages = resp.get("messages", [])
        if not messages:
            break

        for m in messages:
            try:
                msg = service.users().messages().get(
                    userId=user_id,
                    id=m["id"],
                    format="full"
                ).execute()
            except:
                continue

            headers = {h["name"]: h["value"] for h in msg.get("payload", {}).get("headers", [])}
            sender = headers.get("From", "").strip()
            subject = headers.get("Subject", "").strip()
            snippet = msg.get("snippet", "").strip()

            key_source = (sender + "||" + subject + "||" + snippet).lower()
            key = hashlib.md5(key_source.encode("utf-8")).hexdigest()

            if key in seen:
                duplicates.append(m["id"])
            else:
                seen[key] = m["id"]

            fetched_emails += 1
            if fetched_emails >= max_emails:
                break

        page_token = resp.get("nextPageToken")
        if not page_token:
            break

    # Build duplicate details for preview
    duplicate_details = []
    if duplicates:
        for msg_id in duplicates:
            msg = service.users().messages().get(
                userId=user_id, id=msg_id, format="metadata",
                metadataHeaders=["From", "Subject", "Date"]
            ).execute()
            headers = {h["name"]: h["value"] for h in msg.get("payload", {}).get("headers", [])}
            duplicate_details.append({
                "id": msg_id,
                "from": headers.get("From", ""),
                "subject": headers.get("Subject", ""),
                "date": headers.get("Date", ""),
                "snippet": msg.get("snippet", "")
            })

        # Show confirmation page
        return render_template("results.html",
                               fetched=fetched_emails,
                               uniques=len(seen),
                               duplicates=duplicate_details)

    flash(f"Scan complete! Scanned {fetched_emails} emails. No duplicates found.")
    return redirect(url_for("index"))

@app.route("/delete", methods=["POST"])
def delete_duplicates():
    creds = creds_from_session()
    if not creds or not creds.valid:
        return redirect(url_for("index"))

    service = build("gmail", "v1", credentials=creds)
    ids = request.form.getlist("ids")  # selected IDs from results.html

    for msg_id in ids:
        service.users().messages().trash(userId="me", id=msg_id).execute()

    flash(f"Moved {len(ids)} duplicates to Trash successfully.")
    return redirect(url_for("index"))



if __name__ == "__main__":
    app.run("0.0.0.0", port=5000, debug=True)
