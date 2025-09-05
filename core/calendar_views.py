# jobsCode/core/calendar_views.py
# core/calendar_views.py
import os, json
from datetime import timedelta
from django.conf import settings
from django.shortcuts import redirect, get_object_or_404
from django.http import JsonResponse, HttpResponse, HttpResponseBadRequest, HttpResponseForbidden
from django.utils import timezone
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from rest_framework.response import Response

from django.utils.timezone import make_aware
from datetime import timezone as dt_timezone

from core.models import Application
from utils.google import create_google_meet_event

# ★★★ DRF + JWT ★★★
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.views.decorators.csrf import csrf_exempt


BASE_DIR = settings.BASE_DIR
SCOPES = [
    'https://www.googleapis.com/auth/calendar.readonly',
    'https://www.googleapis.com/auth/calendar.events'
]
CLIENT_SECRET_FILE = os.path.join(BASE_DIR, 'credentials.json')

@api_view(["GET"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def google_calendar_init_view(request):
    flow = Flow.from_client_secrets_file(
        os.path.join(settings.BASE_DIR, 'credentials.json'),
        scopes=[
            'https://www.googleapis.com/auth/calendar.readonly',
            'https://www.googleapis.com/auth/calendar.events',
        ],
        redirect_uri=settings.GOOGLE_OAUTH_REDIRECT
    )
    authorization_url, _ = flow.authorization_url(
        prompt='consent',
        access_type='offline',
        include_granted_scopes='true'
    )
    return redirect(authorization_url)

@api_view(["GET"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def google_calendar_redirect_view(request):
    if 'error' in request.GET:
        return HttpResponse("⚠️ მომხმარებელმა უარი თქვა ავტორიზაციაზე.")

    code = request.GET.get("code")
    if not code:
        return HttpResponseBadRequest("Missing 'code'")

    flow = Flow.from_client_secrets_file(
        os.path.join(settings.BASE_DIR, 'credentials.json'),
        scopes=[
            'https://www.googleapis.com/auth/calendar.readonly',
            'https://www.googleapis.com/auth/calendar.events',
        ],
        redirect_uri=settings.GOOGLE_OAUTH_REDIRECT
    )
    flow.fetch_token(code=code)
    credentials = flow.credentials

    user = request.user
    user.google_access_token = credentials.token
    if credentials.refresh_token:
        user.google_refresh_token = credentials.refresh_token

    expiry = getattr(credentials, "expiry", None)
    if expiry is not None and expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=dt_timezone.utc)
    user.google_token_expiry = expiry
    user.save(update_fields=["google_access_token", "google_refresh_token", "google_token_expiry"])

    service = build('calendar', 'v3', credentials=credentials)
    events_result = service.events().list(calendarId='primary', maxResults=5, singleEvents=True, orderBy='startTime').execute()
    preview = [e.get('summary', 'No Title') for e in events_result.get('items', [])]

    return JsonResponse({"detail": "Google Calendar connected", "events_preview": preview})


@api_view(["POST"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
@csrf_exempt
def create_meeting_view(request):
    start = timezone.now() + timedelta(days=1)
    end = start + timedelta(hours=1)

    attendee_email = "aleksandregoguadze@gmail.com"
    meet_link = create_google_meet_event(
        user=request.user,
        summary="გასაუბრება - Jobify",
        description="ეს არის ტესტ გასაუბრება Google Meet-ით",
        start_time=start,
        end_time=end,
        attendee_email=attendee_email
    )
    return JsonResponse({"meet_link": meet_link}, status=201)


@api_view(["POST"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
@csrf_exempt
def create_interview_meeting_view(request, application_id):
    user = request.user
    if getattr(user, "user_type", "") != "employer" and not user.is_superuser:
        return HttpResponseForbidden("მხოლოდ დამსაქმებელს აქვს წვდომა")

    application = get_object_or_404(Application, id=application_id)
    if not user.is_superuser and application.vacancy.employer.user != user:
        return HttpResponseForbidden("არ გაქვს წვდომა ამ განაცხადზე")

    body = {}
    if request.body:
        try:
            body = json.loads(request.body.decode("utf-8"))
        except Exception:
            body = {}

    from django.utils.dateparse import parse_datetime
    start = parse_datetime(body.get("start")) if body.get("start") else timezone.now() + timedelta(days=1)
    end   = parse_datetime(body.get("end"))   if body.get("end")   else start + timedelta(hours=1)

    if start and start.tzinfo is None:
        start = start.replace(tzinfo=dt_timezone.utc)
    if end and end.tzinfo is None:
        end = end.replace(tzinfo=dt_timezone.utc)

    attendee_email = getattr(application.job_seeker, "email", None)
    extra = body.get("attendees") or []

    meet_link = create_google_meet_event(
        user=user,
        summary=f"გასაუბრება - {application.vacancy.title}",
        description=f"გასაუბრება კანდიდატთან {attendee_email}",
        start_time=start,
        end_time=end,
        attendee_email=attendee_email,
        attendees=extra
    )

    application.interview_link = meet_link
    application.interview_start = start
    application.interview_end = end
    application.status = "interview"
    application.save(update_fields=["interview_link", "interview_start", "interview_end", "status"])

    return JsonResponse({
        "application_id": application.id,
        "vacancy": application.vacancy.title,
        "meet_link": meet_link,
        "start": start.isoformat() if start else None,
        "end": end.isoformat() if end else None,
        "attendees": [attendee_email] + [e for e in extra if e],
    }, status=201)
@api_view(["GET"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def google_calendar_status_view(request):
    """
    აბრუნებს მიმდინარე მომხმარებლის Google Calendar კავშირის სტატუსს.
    """
    u = request.user
    now = timezone.now()

    expiry = u.google_token_expiry
    has_access = bool(u.google_access_token)
    has_refresh = bool(u.google_refresh_token)

    # expiry awareness
    if expiry and timezone.is_naive(expiry):
        expiry = expiry.replace(tzinfo=dt_timezone.utc)

    if expiry:
        access_token_expired = expiry <= now
        seconds_left = int((expiry - now).total_seconds())
    else:
        access_token_expired = None
        seconds_left = None

    # ვთვლით დაკავშირებულად, თუ მაინც აქვს refresh_token (access შეიძლება ვადაგასული იყოს — გავალაგებთ refresh-ით)
    is_connected = has_refresh or (has_access and expiry and not access_token_expired)

    return Response({
        "user": {"id": u.id, "email": u.email},
        "is_connected": is_connected,
        "has_access_token": has_access,
        "has_refresh_token": has_refresh,
        "access_token_expires_at": expiry.isoformat() if expiry else None,
        "access_token_seconds_left": seconds_left,
        "access_token_expired": access_token_expired,
        "next_step": "ok" if is_connected else "connect_via_/api/google-calendar/init/"
    })