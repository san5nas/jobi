import jwt
from django.conf import settings
from django.core.mail import send_mail
from datetime import datetime, timedelta

def generate_verification_token(user):
    payload = {
        "user_id": user.id,
        "exp": datetime.utcnow() + timedelta(hours=24),
        "iat": datetime.utcnow(),
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
    # jwt.encode returns bytes in PyJWT<2 or str in PyJWT>=2; ensure str
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    return token

def send_verification_email(user):
    token = generate_verification_token(user)
    # use FRONTEND_HOST if provided; default to local API verify URL
    frontend = getattr(settings, 'FRONTEND_HOST', None)
    if frontend:
        verify_url = f"{frontend}/api/verify-email/?token={token}"
    else:
        verify_url = f"http://127.0.0.1:8000/api/verify-email/?token={token}"

    subject = "Verify your email"
    message = f"Hi {user.username},\n\nClick here to verify your account: {verify_url}\n\nIf you didn’t request this, ignore."
    try:
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=False)
    except Exception:
        # In production, log exception
        pass
