import os
import time
from flask import Flask, session, redirect, url_for, request, render_template, flash
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from rapidfuzz import fuzz
import httplib2

# --- CONFIGURATION ---
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # ok for localhost only
APP_SECRET_KEY = "replace-with-a-random-secret-key"
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
CLIENT_SECRETS_FILE = "client_secrets.json"
OAUTH2_CALLBACK = "http://localhost:5000/oauth2callback"

app = Flask(__name__)
app.secret_key = APP_SECRET_KEY


# --- HELPERS ---
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


def safe_build_service(creds, retries=3):
    """Retry Gmail API connection before failing."""
    for attempt in range(retries):
        try:
            service = build("gmail", "v1", credentials=creds)
            # lightweight call to validate connectivity
            service.users().getProfile(userId="me").execute()
            return service
        except (httplib2.ServerNotFoundError, HttpError, Exception) as e:
            print(f"[GMAIL API ERROR] Attempt {attempt+1}/{retries}: {e}")
            if attempt < retries - 1:
                time.sleep(2)
            else:
                return None


def find_near_duplicates(emails, threshold=85):
    """Near-duplicates based on SUBJECT similarity (85–99%)."""
    near_pairs = []
    n = len(emails)
    for i in range(n):
        s1 = emails[i]["subject"] or ""
        if not s1:
            continue
        for j in range(i + 1, n):
            s2 = emails[j]["subject"] or ""
            if not s2:
                continue
            sim = fuzz.token_sort_ratio(s1, s2)
            if 85 <= sim < 100:
                near_pairs.append({
                    "email1": emails[i],
                    "email2": emails[j],
                    "similarity": round(sim, 2)
                })
    return near_pairs


# --- ROUTES ---
@app.route("/")
def index():
    creds = creds_from_session()
    return render_template("index.html", signed_in=bool(creds and creds.valid))


@app.route("/authorize")
def authorize():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=OAUTH2_CALLBACK,
    )
    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent"
    )
    session["state"] = state
    return redirect(auth_url)


@app.route("/oauth2callback")
def oauth2callback():
    state = session.get("state")
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=state,
        redirect_uri=OAUTH2_CALLBACK,
    )
    flow.fetch_token(authorization_response=request.url)
    session["credentials"] = creds_to_dict(flow.credentials)
    flash("✅ Successfully signed in with Google!")
    return redirect(url_for("index"))


@app.route("/signout")
def signout():
    session.clear()
    flash("👋 You have been signed out.")
    return redirect(url_for("index"))


@app.route("/dedupe", methods=["POST"])
def dedupe():
    """Scan Gmail, group exact duplicates (Sender + Subject), and compute near-duplicates."""
    creds = creds_from_session()
    if not creds or not creds.valid:
        return redirect(url_for("index"))

    service = safe_build_service(creds)
    if not service:
        flash("❌ Could not reach Gmail servers. Please check internet or VPN.")
        return redirect(url_for("index"))

    max_emails = int(request.form.get("max_emails", 100))

    all_emails = []
    page_token = None
    fetched = 0

    while fetched < max_emails:
        resp = service.users().messages().list(
            userId="me",
            maxResults=min(100, max_emails - fetched),
            pageToken=page_token
        ).execute()

        for m in resp.get("messages", []):
            msg = service.users().messages().get(
                userId="me", id=m["id"], format="full"
            ).execute()

            headers = {h["name"]: h["value"] for h in msg.get("payload", {}).get("headers", [])}
            ts = int(msg.get("internalDate", "0"))

            email = {
                "id": m["id"],
                "from": headers.get("From", "").strip(),
                "subject": headers.get("Subject", "").strip(),
                "date": headers.get("Date", ""),
                "snippet": msg.get("snippet", ""),
                "ts": ts
            }
            all_emails.append(email)

            fetched += 1
            if fetched >= max_emails:
                break

        page_token = resp.get("nextPageToken")
        if not page_token:
            break

    # ---- EXACT DUPLICATES (group by sender + subject) ----
    groups_map = {}
    for e in all_emails:
        key = (e["from"], e["subject"])
        groups_map.setdefault(key, []).append(e)

    duplicate_groups = []
    for _, emails in groups_map.items():
        if len(emails) > 1:
            emails_sorted = sorted(emails, key=lambda x: x["ts"], reverse=True)
            duplicate_groups.append(emails_sorted)

    duplicates_flat = [e for grp in duplicate_groups for e in grp]

    # ✅ TRUE DUPLICATE COUNT (each group keeps 1)
    duplicate_count = sum(max(0, len(grp) - 1) for grp in duplicate_groups)

    # ---- NEAR DUPES (85–99% subject match) ----
    near_pairs = find_near_duplicates(all_emails, threshold=85)

    # store for smart delete
    session["duplicate_groups"] = duplicate_groups

    uniques_count = len(all_emails) - duplicate_count

    return render_template(
        "results.html",
        fetched=fetched,
        uniques=uniques_count,
        duplicates=duplicates_flat,
        duplicate_groups=duplicate_groups,
        duplicate_count=duplicate_count,
        similars=near_pairs
    )

@app.route("/delete", methods=["POST"])
def delete_duplicates():
    """Manual delete: trash only the checked IDs."""
    creds = creds_from_session()
    if not creds or not creds.valid:
        return redirect(url_for("index"))

    service = safe_build_service(creds)
    if not service:
        flash("⚠️ Gmail delete request failed. Try again.")
        return redirect(url_for("index"))

    ids = request.form.getlist("ids")
    deleted_mails = []

    for message_id in ids:
        try:
            # read basic info for summary page first
            msg = service.users().messages().get(
                userId="me",
                id=message_id,
                format="metadata",
                metadataHeaders=["From", "Subject", "Date"]
            ).execute()
            headers = {h["name"]: h["value"] for h in msg.get("payload", {}).get("headers", [])}
            deleted_mails.append({
                "id": message_id,
                "from": headers.get("From", ""),
                "subject": headers.get("Subject", ""),
                "date": headers.get("Date", "")
            })
            service.users().messages().trash(userId="me", id=message_id).execute()
        except Exception as e:
            print("Delete error:", e)

    return render_template("deleted.html", kept_one=False, deleted_mails=deleted_mails, kept_mails=[])


@app.route("/smart_delete", methods=["POST"])
def smart_delete():
    """
    Auto-delete per exact duplicate group:
    KEEP the NEWEST (by internalDate), delete the rest.
    """
    creds = creds_from_session()
    if not creds or not creds.valid:
        return redirect(url_for("index"))

    service = safe_build_service(creds)
    if not service:
        flash("⚠️ Gmail delete request failed. Try again.")
        return redirect(url_for("index"))

    duplicate_groups = session.get("duplicate_groups", [])
    deleted_mails = []
    kept_mails = []

    for group in duplicate_groups:
        if not group:
            continue
        # group already sorted newest first in /dedupe
        keep = group[0]
        kept_mails.append({
            "id": keep["id"],
            "from": keep["from"],
            "subject": keep["subject"],
            "date": keep["date"]
        })

        for e in group[1:]:
            try:
                service.users().messages().trash(userId="me", id=e["id"]).execute()
                deleted_mails.append({
                    "id": e["id"],
                    "from": e["from"],
                    "subject": e["subject"],
                    "date": e["date"]
                })
            except Exception as ex:
                print("Smart delete error:", ex)

    return render_template("deleted.html", kept_one=True, deleted_mails=deleted_mails, kept_mails=kept_mails)


# --- RUN APP ---
if __name__ == "__main__":
    app.run("0.0.0.0", port=5000, debug=True)
