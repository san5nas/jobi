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

from utils.google import get_valid_google_credentials

from django.core.mail import send_mail


from django.utils.timezone import make_aware
from datetime import timezone as dt_timezone

from django.contrib.auth import get_user_model

from core.models import Application
from utils.google import create_google_meet_event

# ★★★ DRF + JWT ★★★
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.views.decorators.csrf import csrf_exempt
from django.core.signing import TimestampSigner, BadSignature
from django.core.validators import validate_email
from django.core.exceptions import ValidationError

def _is_valid_email(addr: str) -> bool:
    if not isinstance(addr, str):
        return False
    s = addr.strip()
    if not s:
        return False
    try:
        validate_email(s)
        return True
    except ValidationError:
        return False

signer = TimestampSigner()

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
    """
    ინიციალიზაცია Google Calendar OAuth2-სთვის.
    JWT ავტორიზაციით user-ს ვიღებთ და ვუშვებთ Google OAuth-ში.
    """
    user = request.user

    flow = Flow.from_client_secrets_file(
        os.path.join(settings.BASE_DIR, "credentials.json"),
        scopes=[
            "https://www.googleapis.com/auth/calendar.readonly",
            "https://www.googleapis.com/auth/calendar.events",
        ],
        redirect_uri=settings.GOOGLE_CALENDAR_REDIRECT,
    )

    # state აღარ გვჭირდება → პირდაპირ user.id გადავაწეროთ
    authorization_url, _ = flow.authorization_url(
        prompt="consent",
        access_type="offline",
        include_granted_scopes="true",
        state=str(user.id),   # უბრალოდ user.id
    )

    return redirect(authorization_url)


@api_view(["GET"])
@authentication_classes([])  # callback-ზე ავტორიზაცია არ გვჭირდება
@permission_classes([AllowAny])
def google_calendar_redirect_view(request):
    if "error" in request.GET:
        return HttpResponse("⚠️ მომხმარებელმა უარი თქვა ავტორიზაციაზე.")

    code = request.GET.get("code")
    state = request.GET.get("state")
    if not code or not state:
        return HttpResponseBadRequest("Missing code or state")

    # state = user.id პირდაპირ
    user_id = state
    User = get_user_model()
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return HttpResponseBadRequest("User not found")

    flow = Flow.from_client_secrets_file(
        os.path.join(settings.BASE_DIR, "credentials.json"),
        scopes=[
            "https://www.googleapis.com/auth/calendar.readonly",
            "https://www.googleapis.com/auth/calendar.events",
        ],
        redirect_uri=settings.GOOGLE_CALENDAR_REDIRECT,
    )
    flow.fetch_token(code=code)
    credentials = flow.credentials

    # შევინახოთ user-ზე
    user.google_access_token = credentials.token
    if credentials.refresh_token:
        user.google_refresh_token = credentials.refresh_token
    if getattr(credentials, "expiry", None):
        user.google_token_expiry = credentials.expiry
    user.save(update_fields=["google_access_token", "google_refresh_token", "google_token_expiry"])

    return JsonResponse({"detail": "Google Calendar connected ✅"})

@api_view(["POST"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
@csrf_exempt
def create_interview_meeting_view(request, application_id):
    from django.utils.dateparse import parse_datetime

    user = request.user
    application = get_object_or_404(Application, id=application_id)

    # --- წვდომის კონტროლი ---
    if user.is_superuser:
        pass
    elif user.user_type == "employer":
        if application.vacancy.employer.user != user:
            return JsonResponse({"error": "არ გაქვს წვდომა ამ განაცხადზე"}, status=403)
    elif user.user_type == "job_seeker":
        return JsonResponse({"error": "სამუშაოს მაძიებელს ინტერვიუს შექმნა არ შეუძლია"}, status=403)
    else:
        return JsonResponse({"error": "არ გაქვს წვდომა"}, status=403)

    # --- სხეულის დამუშავება ---
    body = {}
    if request.body:
        try:
            body = json.loads(request.body.decode("utf-8"))
        except Exception:
            body = {}

    start = parse_datetime(body.get("start")) if body.get("start") else timezone.now() + timedelta(days=1)
    end = parse_datetime(body.get("end")) if body.get("end") else start + timedelta(hours=1)

    if start and start.tzinfo is None:
        start = start.replace(tzinfo=dt_timezone.utc)
    if end and end.tzinfo is None:
        end = end.replace(tzinfo=dt_timezone.utc)

    organizer_email = user.email.strip().lower()
    attendee_email_raw = getattr(application.job_seeker, "email", None)
    attendee_email = attendee_email_raw.strip().lower() if _is_valid_email(attendee_email_raw) else None

    extra_raw = body.get("attendees") or []
    extra = []
    for e in extra_raw:
        if isinstance(e, str):
            s = e.strip().lower()
            if _is_valid_email(s) and s != attendee_email and s != organizer_email:
                extra.append(s)
        elif isinstance(e, dict):
            s = (e.get("email") or "").strip().lower()
            if _is_valid_email(s) and s != attendee_email and s != organizer_email:
                extra.append(s)

    # --- მონაწილეთა სია (არ ვამატებთ ორგანიზატორს!) ---
# --- მონაწილეთა სია (✅ ორგანიზატორიც დაემატოს!) ---
    attendees_list = []
    
    # ✅ Always include organizer (ინტერვიუს შემქმნელი)
    if organizer_email:
        attendees_list.append({"email": organizer_email})
    
    # ✅ Add main candidate
    if attendee_email and attendee_email != organizer_email:
        attendees_list.append({"email": attendee_email})
    
    # ✅ Add additional guests
    for e in extra:
        if e != organizer_email and e != attendee_email:
            attendees_list.append({"email": e})
    
    # --- Google Meet ღონისძიების შექმნა ---
    meet_link, event_id = create_google_meet_event(
        user=request.user,
        summary=f"ინტერვიუ: {application.vacancy.title}",
        description=f"ინტერვიუ კანდიდატთან {application.job_seeker.get_full_name() or application.job_seeker.email}",
        start_time=start,
        end_time=end,
        attendee_email=None,  # არ ვიყენებთ ცალკე
        attendees=attendees_list,
    )

    if not meet_link or not event_id:
        return Response(
            {
                "detail": "Google Calendar connection missing or expired. Please re-connect Google.",
                "action": "reauth",
                "reauth_url": "/api/google-calendar/init/"
            },
            status=401
        )

    # --- Application განახლება ---
    application.interview_link = meet_link
    application.interview_start = start
    application.interview_end = end
    application.interview_event_id = event_id
    application.status = "interview"
    application.save(update_fields=["interview_link", "interview_start", "interview_end", "interview_event_id", "status"])

    # --- Email შეტყობინება (არასავალდებულო) ---
    try:
        employer = user
        candidate = application.job_seeker
        vacancy_title = application.vacancy.title
        candidate_name = (candidate.get_full_name() or candidate.username or candidate.email)

        subject = f"დაჯავშნილია შეხვედრა კანდიდატთან — {candidate_name} ({vacancy_title})"
        body = f"ინტერვიუ დაინიშნა {start} - {end}."
        send_mail(
            subject=subject,
            message=body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[employer.email, candidate.email],
            fail_silently=True,
        )
    except Exception:
        pass

    return JsonResponse({
        "application_id": application.id,
        "vacancy": application.vacancy.title,
        "meet_link": meet_link,
        "start": start.isoformat() if start else None,
        "end": end.isoformat() if end else None,
        "attendees": [e["email"] for e in attendees_list],
        "event_id": event_id
    }, status=201)



@api_view(["POST"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
@csrf_exempt
def create_meeting_view(request):
    start = timezone.now() + timedelta(days=1)
    end = start + timedelta(hours=1)

    attendee_email = "aleksandregoguadze@gmail.com"
    meet_link, event_id = create_google_meet_event(
        user=request.user,
        summary="გასაუბრება - Jobify",
        description="ეს არის ტესტ გასაუბრება Google Meet-ით",
        start_time=start,
        end_time=end,
        attendee_email=attendee_email
    )

    if not meet_link:
        return JsonResponse({"error": "Google Calendar not connected"}, status=400)
    
    return JsonResponse({
    "meet_link": meet_link,
    "event_id": event_id,
    "start": start.isoformat(),
    "end": end.isoformat(),
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
# core/calendar_views.py

@api_view(["GET"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def interview_status_view(request, application_id):
    """
    აბრუნებს Application-ზე შექმნილი ინტერვიუს ღონისძიების მონაწილეთა სტატუსებს.
    
    წვდომა:
    - Employer → მხოლოდ თავისი ვაკანსიების აპლიკაციებზე
    - Superuser → ყველა აპლიკაციაზე
    - Job seeker → მხოლოდ თავისი აპლიკაციებზე
    """
    user = request.user
    application = get_object_or_404(Application, id=application_id)

    # --- წვდომის კონტროლი ---
    if user.is_superuser:
        pass  # superuser-ს სრული წვდომა აქვს
    elif user.user_type == "employer":
        if application.vacancy.employer.user != user:
            return JsonResponse({"error": "არ გაქვს წვდომა ამ განაცხადზე"}, status=403)
    elif user.user_type == "job_seeker":
        if application.job_seeker != user:
            return JsonResponse({"error": "არ გაქვს წვდომა ამ განაცხადზე"}, status=403)
    else:
        return JsonResponse({"error": "არ გაქვს წვდომა"}, status=403)

    # --- თუ ინტერვიუ არ არსებობს ---
    if not application.interview_event_id:
        return JsonResponse({
            "application_id": application.id,
            "status": "not_found",
            "detail": "ამ განაცხადზე ინტერვიუს ღონისძიების ID არ არის შენახული."
        }, status=404)

    # --- Google Calendar API გამოძახება ---
    from utils.google import get_event_attendance_status
    statuses, updated = get_event_attendance_status(user, application.interview_event_id)

    candidate_email = getattr(application.job_seeker, "email", None)
    candidate_status = statuses.get(candidate_email) if candidate_email else None

    # --- Response ---
    return JsonResponse({
        "application_id": application.id,
        "event_id": application.interview_event_id,
        "status": "connected",
        "updated": updated,
        "candidate": {
            "email": candidate_email,
            "response": candidate_status
        },
        "attendees": statuses,  # {email: responseStatus}
    }, status=200)

# core/calendar_views.py


@api_view(["GET"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def google_calendar_events_view(request):
    """
    აბრუნებს მიმდინარე მომხმარებლის Google Calendar-ის მომავალი ღონისძიებებს.
    """
    creds = get_valid_google_credentials(request.user)
    if not creds:
        return JsonResponse({"error": "Google Calendar not connected"}, status=401)

    service = build("calendar", "v3", credentials=creds)

    events_result = service.events().list(
        calendarId="primary",
        maxResults=10,
        singleEvents=True,
        orderBy="startTime"
    ).execute()

    events = events_result.get("items", [])
    return JsonResponse(events, safe=False)
