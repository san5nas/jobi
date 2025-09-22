import uuid
from datetime import datetime, timezone as dt_timezone, timedelta

from django.conf import settings
from django.utils.timezone import make_aware, is_naive, get_current_timezone

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleRequest
from googleapiclient.discovery import build
from google.auth.exceptions import RefreshError

from django.utils.timezone import get_current_timezone_name

from typing import Tuple, Dict, Optional
from django.utils import timezone
# --- Scope-ები ---
SCOPES = [
    "https://www.googleapis.com/auth/calendar.readonly",
    "https://www.googleapis.com/auth/calendar.events",
]

REFRESH_SKEW = 300  # 5 წუთით ადრე განახლდეს access token


def _make_expiry_aware(expiry):
    if not expiry:
        return None
    return expiry if expiry.tzinfo else expiry.replace(tzinfo=dt_timezone.utc)


def get_valid_google_credentials(user):
    """
    იღებს მომხმარებლის Credentials-ს DB-დან.
    საჭიროების შემთხვევაში აახლებს access_token-ს refresh_token-ით.
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

    now = datetime.now(dt_timezone.utc)
    expiry_aware = _make_expiry_aware(getattr(creds, "expiry", user.google_token_expiry))
    needs_refresh = (
        (expiry_aware is None)
        or (expiry_aware - now <= timedelta(seconds=REFRESH_SKEW))
        or (not creds.valid)
    )

    if needs_refresh and creds.refresh_token:
        try:
            creds.refresh(GoogleRequest())
        except RefreshError:
            # refresh token გაუქმდა → გავასუფთავოთ user ველები
            user.google_access_token = None
            user.google_refresh_token = None
            user.google_token_expiry = None
            user.save(update_fields=["google_access_token", "google_refresh_token", "google_token_expiry"])
            return None

        # განახლების შემდეგ შენახვა
        user.google_access_token = creds.token
        user.google_token_expiry = _make_expiry_aware(getattr(creds, "expiry", None))
        new_refresh = getattr(creds, "refresh_token", None)
        if new_refresh and new_refresh != user.google_refresh_token:
            user.google_refresh_token = new_refresh
        user.save(update_fields=["google_access_token", "google_token_expiry", "google_refresh_token"])

    return creds


def create_google_meet_event(user, summary, description, start_time, end_time, attendee_email=None, attendees=None):
    creds = get_valid_google_credentials(user)
    if not creds:
        print("❌ Google Calendar not connected for this user")
        return None, None

    service = build("calendar", "v3", credentials=creds)
    tz = "Asia/Tbilisi"

    # დროს ვაქცევთ aware ფორმატში
    if is_naive(start_time):
        start_time = make_aware(start_time, get_current_timezone())
    if is_naive(end_time):
        end_time = make_aware(end_time, get_current_timezone())

    # დამუშავებული მონაწილეები
    attendees_list = attendees or []

    try:
        event = {
            "summary": summary,
            "description": description,
            "start": {"dateTime": start_time.isoformat(), "timeZone": tz},
            "end": {"dateTime": end_time.isoformat(), "timeZone": tz},
            "attendees": attendees_list,
            "conferenceData": {
                "createRequest": {
                    "requestId": f"{user.id}-{timezone.now().timestamp()}",
                    "conferenceSolutionKey": {"type": "hangoutsMeet"},
                }
            }
        }
        
        created_event = service.events().insert(
            calendarId="primary",
            body=event,
            conferenceDataVersion=1,
            sendUpdates="all"  # ← ეს გადაამოწმე ნამდვილად ასეა თუ არა
        ).execute()
        

        meet_link = created_event.get("hangoutLink")
        event_id = created_event.get("id")
        return meet_link, event_id
    except Exception as e:
        print("Google Meet creation error:", e)
        return None, None


def get_event_attendance_status(user, event_id: str) -> Tuple[Dict[str, str], Optional[str]]:
    """
    აბრუნებს {email: responseStatus} mapping-ს და event-ის 'updated' timestamp-ს.
    """
    creds = get_valid_google_credentials(user)
    if not creds:
        return {}, None

    service = build("calendar", "v3", credentials=creds)
    ev = service.events().get(calendarId="primary", eventId=event_id).execute()

    attendees = ev.get("attendees", []) or []
    statuses = {a.get("email", ""): a.get("responseStatus", "") for a in attendees}
    updated = ev.get("updated")

    return statuses, updated
