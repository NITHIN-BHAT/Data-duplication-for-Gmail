import os
import hashlib
from flask import Flask, session, redirect, url_for, request, render_template, flash, jsonify
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from rapidfuzz import fuzz

# --- CONFIGURATION ---
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
APP_SECRET_KEY = "replace-with-a-random-secret-key"
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
CLIENT_SECRETS_FILE = "client_secrets.json"
OAUTH2_CALLBACK = "http://localhost:5000/oauth2callback"

app = Flask(__name__)
app.secret_key = APP_SECRET_KEY


# --- HELPER FUNCTIONS ---
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


def find_near_duplicates(emails, threshold=85):
    exact_duplicates = []
    near_duplicates = []

    for i in range(len(emails)):
        for j in range(i + 1, len(emails)):
            sub1 = emails[i].get("subject", "")
            sub2 = emails[j].get("subject", "")
            if not sub1 or not sub2:
                continue

            similarity = fuzz.token_sort_ratio(sub1, sub2)
            pair = {
                "email1": emails[i],
                "email2": emails[j],
                "similarity": round(similarity, 2)
            }

            if similarity == 100:
                exact_duplicates.append(pair)
            elif threshold <= similarity < 100:
                near_duplicates.append(pair)

    return exact_duplicates, near_duplicates


# --- ROUTES ---
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
    flash("Successfully signed in with Google!")
    return redirect(url_for("index"))


@app.route("/signout")
def signout():
    session.clear()
    flash("You have been signed out.")
    return redirect(url_for("index"))


@app.route("/dedupe", methods=["POST"])
def dedupe():
    creds = creds_from_session()
    if not creds or not creds.valid:
        return redirect(url_for("index"))

    service = build("gmail", "v1", credentials=creds)
    user_id = "me"

    max_emails = int(request.form.get("max_emails", 50))
    seen = {}
    all_emails = []
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
            except Exception:
                continue

            headers = {h["name"]: h["value"] for h in msg.get("payload", {}).get("headers", [])}
            sender = headers.get("From", "")
            subject = headers.get("Subject", "")
            snippet = msg.get("snippet", "")
            date = headers.get("Date", "")

            email_data = {
                "id": m["id"],
                "from": sender,
                "subject": subject,
                "date": date,
                "snippet": snippet
            }

            all_emails.append(email_data)
            fetched_emails += 1
            if fetched_emails >= max_emails:
                break

        page_token = resp.get("nextPageToken")
        if not page_token:
            break

    # Store emails in session
    session["scanned_emails"] = all_emails

    # Detect duplicates
    exact_pairs, near_duplicates = find_near_duplicates(all_emails)
    duplicates = [p["email1"] for p in exact_pairs]

    return render_template(
        "results.html",
        fetched=fetched_emails,
        uniques=len(all_emails) - len(duplicates),
        duplicates=duplicates,
        similars=near_duplicates
    )


@app.route("/delete", methods=["POST"])
def delete_duplicates():
    creds = creds_from_session()
    if not creds or not creds.valid:
        return redirect(url_for("index"))

    service = build("gmail", "v1", credentials=creds)
    ids = request.form.getlist("ids")

    scanned_data = session.get("scanned_emails", [])
    if not scanned_data:
        flash("No scanned email data found. Please rescan first.")
        return redirect(url_for("index"))

    exact_duplicates, _ = find_near_duplicates(scanned_data)
    grouped = {}
    for pair in exact_duplicates:
        sub = pair["email1"]["subject"]
        grouped.setdefault(sub, set())
        grouped[sub].add(pair["email1"]["id"])
        grouped[sub].add(pair["email2"]["id"])

    deleted_ids = []
    for selected_id in ids:
        for subject, id_group in grouped.items():
            if selected_id in id_group:
                ids_to_delete = list(id_group)[1:]
                for msg_id in ids_to_delete:
                    try:
                        service.users().messages().trash(userId="me", id=msg_id).execute()
                        deleted_ids.append(msg_id)
                    except Exception as e:
                        print(f"Error deleting message {msg_id}: {e}")
                break

    flash(f"Deleted {len(deleted_ids)} duplicates, keeping one from each group.")
    return redirect(url_for("index"))


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


@app.route("/terms")
def terms():
    return render_template("terms.html")


if __name__ == "__main__":
    app.run("0.0.0.0", port=5000, debug=True)
