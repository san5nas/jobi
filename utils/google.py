# jobsCode/utils/google.py
import uuid
from django.conf import settings
from django.utils import timezone
from django.utils.timezone import make_aware
from datetime import datetime

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleRequest
from googleapiclient.discovery import build

SCOPES = [
    "https://www.googleapis.com/auth/calendar.readonly",
    "https://www.googleapis.com/auth/calendar.events",
]

def _make_expiry_aware(expiry: datetime | None):
    if not expiry:
        return None
    if expiry.tzinfo is None:
        return make_aware(expiry, timezone=timezone.utc)
    return expiry

def get_valid_google_credentials(user):
    """
    ქმნის Credentials ობიექტს user.google_* ველებიდან.
    თუ ვადა ამოწურულია და გვაქვს refresh_token, ავტომატურად აახლებინებს და
    ახალ access_token/expiry-ს შეინახავს user-ზე.
    """
    if not user.google_access_token or not user.google_refresh_token:
        return None

    creds = Credentials(
        token=user.google_access_token,
        refresh_token=user.google_refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=getattr(settings, "GOOGLE_CLIENT_ID", None),
        client_secret=getattr(settings, "GOOGLE_CLIENT_SECRET", None),
        scopes=SCOPES,
    )

    if not creds.valid and creds.refresh_token:
        creds.refresh(GoogleRequest())
        user.google_access_token = creds.token
        user.google_token_expiry = _make_expiry_aware(getattr(creds, "expiry", None))
        user.save(update_fields=["google_access_token", "google_token_expiry"])

    return creds

def create_google_meet_event(
    user,
    summary: str,
    description: str,
    start_time,   # aware datetime
    end_time,     # aware datetime
    attendee_email: str | None,
    attendees: list[str] | None = None,
):
    """
    ქმნის Google Calendar event-ს Meet-ით და აბრუნებს meet_link-ს.
    """
    creds = get_valid_google_credentials(user)
    if not creds:
        raise RuntimeError("Google is not connected for this user. Call /api/google-calendar/init/ first.")

    service = build("calendar", "v3", credentials=creds)

    attendees_list = []
    if attendee_email:
        attendees_list.append({"email": attendee_email})
    if attendees:
        for a in attendees:
            if a and {"email": a} not in attendees_list:
                attendees_list.append({"email": a})

    event = {
        "summary": summary,
        "description": description,
        "start": {"dateTime": start_time.isoformat()},
        "end": {"dateTime": end_time.isoformat()},
        "attendees": attendees_list,
        "conferenceData": {
            "createRequest": {
                "requestId": f"jobify-{uuid.uuid4().hex}",
                "conferenceSolutionKey": {"type": "hangoutsMeet"},
            }
        },
        "reminders": {"useDefault": True},
    }

    created = service.events().insert(
        calendarId="primary",
        body=event,
        conferenceDataVersion=1,
    ).execute()

    return created.get("hangoutLink")
