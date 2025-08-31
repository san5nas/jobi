from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.core.mail import send_mail
from django.conf import settings

from .models import User, JobSeekerProfile, EmployerProfile, AdminProfile

# cache old user_type before save
@receiver(pre_save, sender=User)
def cache_old_user_type(sender, instance, **kwargs):
    if instance.pk:
        try:
            old = sender.objects.only('user_type').get(pk=instance.pk)
            instance._old_user_type = old.user_type
        except sender.DoesNotExist:
            instance._old_user_type = None
    else:
        instance._old_user_type = None

# Ensure profile exists for user_type and remove other profiles
@receiver(post_save, sender=User)
def ensure_profile_for_user_type(sender, instance, created, **kwargs):
    # if user_type empty — do nothing
    if not instance.user_type:
        return

    def ensure_only(keep_model):
        if keep_model is not AdminProfile:
            AdminProfile.objects.filter(user=instance).delete()
        if keep_model is not JobSeekerProfile:
            JobSeekerProfile.objects.filter(user=instance).delete()
        if keep_model is not EmployerProfile:
            EmployerProfile.objects.filter(user=instance).delete()

    if instance.user_type == "job_seeker":
        ensure_only(JobSeekerProfile)
        JobSeekerProfile.objects.get_or_create(user=instance)
    elif instance.user_type == "employer":
        ensure_only(EmployerProfile)
        EmployerProfile.objects.get_or_create(user=instance)
    elif instance.user_type == "admin":
        ensure_only(AdminProfile)
        AdminProfile.objects.get_or_create(user=instance)

# Notify admin when new user is created
@receiver(post_save, sender=User)
def notify_admin_on_user_creation(sender, instance, created, **kwargs):
    if not created:
        return

    admin_emails = []
    if settings.ADMIN_EMAIL:
        # allow comma-separated admin emails
        admin_emails = [e.strip() for e in settings.ADMIN_EMAIL.split(',') if e.strip()]

    if not admin_emails:
        # nothing to notify to
        return

    subject = "New user registered"
    message_lines = [f"Username: {instance.username}", f"Email: {instance.email}", f"User type: {instance.user_type}"]
    # If employer profile exists, include company_name
    try:
        employer_profile = EmployerProfile.objects.filter(user=instance).first()
        if employer_profile:
            message_lines.append(f"Company: {employer_profile.company_name}")
            message_lines.append(f"Contact person: {employer_profile.contact_person}")
            message_lines.append(f"Approved by admin: {employer_profile.is_approved_by_admin}")
    except Exception:
        pass

    message = "\n".join(message_lines)
    try:
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, admin_emails, fail_silently=False)
    except Exception:
        # Do not break registration on email failure; consider logging in prod
        pass
