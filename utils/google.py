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

from googleapiclient.errors import HttpError

SCOPES = [
    "https://www.googleapis.com/auth/calendar.readonly",
    "https://www.googleapis.com/auth/calendar.events",
    "https://www.googleapis.com/auth/forms.body",
    "https://www.googleapis.com/auth/forms.responses.readonly",
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






def create_google_form(user, title="Jobify Test", description=None):
    """
    ქმნის ახალ Google Form-ს user-ის სახელით.
    create: მხოლოდ info.title
    დანარჩენი (description და ა.შ.) → batchUpdate-ით.
    აბრუნებს: {formId, responderUri, title}
    """
    creds = get_valid_google_credentials(user)
    if not creds:
        return None

    try:
        service = build("forms", "v1", credentials=creds)

        # ✅ create-ზე მხოლოდ title შეიძლება
        created = service.forms().create(
            body={"info": {"title": title}}
        ).execute()

        form_id = created["formId"]

        # (არჩევითი) description-ს ვამატებთ batchUpdate-ით
        if description:
            service.forms().batchUpdate(
                formId=form_id,
                body={
                    "requests": [
                        {
                            "updateFormInfo": {
                                "info": {"description": description},
                                "updateMask": "description",
                            }
                        }
                    ]
                },
            ).execute()

        # ზოგჯერ responderUri create-ის პასუხში არაა -> ერთხელ წავიკითხოთ get-ით
        meta = service.forms().get(formId=form_id).execute()
        return {
            "formId": form_id,
            "responderUri": meta.get("responderUri"),
            "title": meta["info"].get("title"),
        }

    except HttpError as error:
        print(f"Forms API error: {error}")
        return None


# utils/google.py  (დაამატე create_google_form-ის ქვემოთ)

def create_form_with_items(
    user,
    title: str,
    description: str | None = None,
    collect_email: bool = True,
    is_quiz: bool = True,
    items: list[dict] | None = None,
):

    creds = get_valid_google_credentials(user)
    if not creds:
        return None

    service = build("forms", "v1", credentials=creds)

    # 1) create → მხოლოდ title
    created = service.forms().create(body={"info": {"title": title}}).execute()
    form_id = created["formId"]

    # 2) batchUpdate – settings + description + კითხვები
    requests = []

    if is_quiz:
        requests.append({
            "updateSettings": {
                "settings": {"quizSettings": {"isQuiz": True}},
                "updateMask": "quizSettings.isQuiz",
            }
        })
    if collect_email:
        requests.append({
            "updateSettings": {
                "settings": {"emailCollectionType": "RESPONDER_INPUT"},
                "updateMask": "emailCollectionType",
            }
        })
    if description:
        requests.append({
            "updateFormInfo": {
                "info": {"description": description},
                "updateMask": "description",
            }
        })

    idx = 0
    for it in (items or []):
        t = (it.get("type") or "").lower()
        title_i = it.get("title") or "Untitled"
        required = bool(it.get("required", True))

        if t == "short":
            req = {
                "createItem": {
                    "item": {
                        "title": title_i,
                        "questionItem": {
                            "question": {"required": required, "textQuestion": {}}
                        }
                    },
                    "location": {"index": idx},
                }
            }
        elif t == "mcq":
            options = it.get("options") or []
            q = {
                "required": required,
                "choiceQuestion": {
                    "type": "RADIO",
                    "options": [{"value": o} for o in options],
                    "shuffle": False,
                }
            }
            ci = it.get("correct_index")
            if isinstance(ci, int) and 0 <= ci < len(options):
                q["grading"] = {
                    "pointValue": int(it.get("points", 1)),
                    "correctAnswers": {"answers": [{"value": options[ci]}]},
                }
            req = {
                "createItem": {
                    "item": {"title": title_i, "questionItem": {"question": q}},
                    "location": {"index": idx},
                }
            }
        else:
            continue

        requests.append(req)
        idx += 1

    if requests:
        service.forms().batchUpdate(formId=form_id, body={"requests": requests}).execute()

    meta = service.forms().get(formId=form_id).execute()
    return {
        "formId": form_id,
        "responderUri": meta.get("responderUri"),
        "title": meta["info"].get("title"),
    }




def get_form_responses(user, form_id):
    creds = get_valid_google_credentials(user)
    if not creds:
        return []

    service = build("forms", "v1", credentials=creds)

    all_responses = []
    page_token = None
    while True:
        resp = service.forms().responses().list(
            formId=form_id,
            pageToken=page_token,
            pageSize=500,
        ).execute()
        all_responses.extend(resp.get("responses", []))
        page_token = resp.get("nextPageToken")
        if not page_token:
            break

    return all_responses


def enable_quiz(user, form_id: str, collect_email: bool = True):
    """ჩართე Quiz და Email-ების შეგროვება."""
    creds = get_valid_google_credentials(user)
    if not creds:
        return

    service = build("forms", "v1", credentials=creds)

    settings = {
        "quizSettings": {"isQuiz": True}
    }
    update_mask = ["quizSettings.isQuiz"]

    if collect_email:
        
        settings["emailCollectionType"] = "RESPONDER_INPUT"
        update_mask.append("emailCollectionType")

    service.forms().batchUpdate(
        formId=form_id,
        body={
            "requests": [
                {
                    "updateSettings": {
                        "settings": settings,
                        "updateMask": ",".join(update_mask),
                    }
                }
            ]
        },
    ).execute()



def add_short_answer(user, form_id: str, title: str, required: bool = True, index: int = 0):
    """დაამატე Short answer კითხვა."""
    creds = get_valid_google_credentials(user)
    service = build("forms", "v1", credentials=creds)
    service.forms().batchUpdate(
        formId=form_id,
        body={
            "requests": [
                {
                    "createItem": {
                        "item": {
                            "title": title,
                            "questionItem": {
                                "question": {
                                    "required": required,
                                    "textQuestion": {}
                                }
                            },
                        },
                        "location": {"index": index},
                    }
                }
            ]
        },
    ).execute()


def add_multiple_choice(user, form_id: str, title: str, options: list[str],
                        correct_index: int | None = None, points: int = 1, index: int = 0):
    """დაამატე Multiple Choice კითხვა; თუ correct_index გადმოგვეცა → ქულებიც დაეჯგუფება."""
    creds = get_valid_google_credentials(user)
    service = build("forms", "v1", credentials=creds)

    item_question = {
        "required": True,
        "choiceQuestion": {
            "type": "RADIO",
            "options": [{"value": o} for o in options],
            "shuffle": False,
        },
    }

    if correct_index is not None and 0 <= correct_index < len(options):
        item_question["grading"] = {
            "pointValue": points,
            "correctAnswers": {"answers": [{"value": options[correct_index]}]},
        }

    service.forms().batchUpdate(
        formId=form_id,
        body={
            "requests": [
                {
                    "createItem": {
                        "item": {
                            "title": title,
                            "questionItem": {"question": item_question},
                        },
                        "location": {"index": index},
                    }
                }
            ]
        },
    ).execute()
