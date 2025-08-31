from django.core.mail import EmailMessage
import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "job_platform_project.settings")
django.setup()

email = EmailMessage(
    subject="ტესტი მეილი",  # Subject ქართულად
    body="ეს არის ტესტი მეილი Django-დან",  # Body ქართულად
    from_email="your_email@gmail.com",  # შენი მეილი
    to=["admin_email@gmail.com"],  # ადმინის მეილი
)
email.content_subtype = "plain"  # text
email.encoding = "utf-8"  # აქ UTF-8 კოდირება
email.send(fail_silently=False)

print("Email sent!")
