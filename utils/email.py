from django.core.mail import send_mail
from django.conf import settings
from django.core.mail import  EmailMultiAlternatives
from django.template.loader import render_to_string
from django.conf import settings

def send_verification_email(user, token):
    verify_link = f"http://localhost:8000/api/verify-email/?token={token}"
    subject = "Confirm your email"
    message = f"Hello {user.username},\n\nClick here to verify your account:\n{verify_link}"

    # ❌ დროებით არ ვაგზავნით
    # send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])

    # ✅ DEBUG: კონსოლში გამოიტანს
    print(f"[DEBUG] Verification email to {user.email}: {verify_link}")


def send_password_reset_email(to, subject, template_name, context):
    html_content = render_to_string(template_name, context)
    msg = EmailMultiAlternatives(subject, '', settings.DEFAULT_FROM_EMAIL, to)
    msg.attach_alternative(html_content, "text/html")
    msg.send()
