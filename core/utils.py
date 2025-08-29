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
    return token

def send_verification_email(user):
    token = generate_verification_token(user)
    verify_url = f"http://127.0.0.1:8000/api/verify-email/?token={token}"
    subject = "Verify your email"
    message = f"Hi {user.username},\n\nClick here to verify your account: {verify_url}\n\nIf you didn’t request this, ignore."
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])
