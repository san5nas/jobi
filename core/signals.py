from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.core.mail import send_mail
from django.conf import settings
from .models import User,Invoice, JobSeekerProfile, EmployerProfile, AdminProfile, Vacancy # <-- Vacancy მოდელიც დაამატეთ აქ

from django.core.signing import TimestampSigner
from django.utils import timezone
from .models import User
from utils.email import send_verification_email
from .models import PurchasedService
from .models import Application  


signer = TimestampSigner()

@receiver(post_save, sender=User)
def send_verification_on_register(sender, instance, created, **kwargs):
    if created and instance.email:
        # Token with timestamp
        token = signer.sign(instance.pk)
        send_verification_email(instance, token)
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


@receiver(post_save, sender=Vacancy)
def notify_admin_on_new_vacancy(sender, instance, created, **kwargs):

    if not created:
        return
    admin_emails = []
    if getattr(settings, "ADMIN_EMAIL", None):
        admin_emails = [e.strip() for e in settings.ADMIN_EMAIL.split(",") if e.strip()]
    if not admin_emails:
        return

    employer_name = getattr(instance.employer, "company_name", instance.employer_id)
    subject = f"ახალი ვაკანსია მოლოდინში: {instance.title}"
    body = (
        f"დამსაქმებელი: {employer_name}\n"
        f"გამოქვეყნებულია?: {instance.is_published}\n"
        f"დამტკიცებულია?: {instance.is_approved}\n\n"
        "გთხოვთ, შეამოწმოთ და დაამტკიცოთ admin პანელიდან."
    )
    try:
        send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, admin_emails, fail_silently=True)
    except Exception:
        pass


# --- ახალი: ინვოისის შექმნის შეტყობინება ---
@receiver(post_save, sender=Invoice)
def notify_admin_on_invoice_created(sender, instance, created, **kwargs):
    if not created:
        return

    # ამოვიღოთ ადმინების მისამართ(ებ)ი settings.ADMIN_EMAIL-დან (coma-separated მხარდაჭერილია)
    admin_emails = []
    if getattr(settings, "ADMIN_EMAIL", None):
        admin_emails = [e.strip() for e in settings.ADMIN_EMAIL.split(",") if e.strip()]
    if not admin_emails:
        return

    service_name = getattr(instance.service, "name", "No Service")
    subject = f"ახალი ინვოისი #{instance.id}"
    body = (
        f"მომხმარებელი: {instance.user.email}\n"
        f"სერვისი: {service_name}\n"
        f"თანხა: {instance.amount}\n"
        f"სტატუსი: {instance.status}\n"
        f"შექმნის თარიღი: {instance.created_at:%Y-%m-%d %H:%M}\n"
    )
    try:
        send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, admin_emails, fail_silently=True)
    except Exception:
        pass

#  როცა სტატუსი unpaid→paid იცვლება, ადმინების შეტყობინება ---
@receiver(pre_save, sender=Invoice)
def cache_old_invoice_status(sender, instance, **kwargs):
    if instance.pk:
        try:
            old = sender.objects.only("status").get(pk=instance.pk)
            instance._old_status = old.status
        except sender.DoesNotExist:
            instance._old_status = None
    else:
        instance._old_status = None

@receiver(post_save, sender=Invoice)
def notify_admin_on_invoice_paid(sender, instance, created, **kwargs):
    if created:
        return
    if getattr(instance, "_old_status", None) != "paid" and instance.status == "paid":
        admin_emails = []
        if getattr(settings, "ADMIN_EMAIL", None):
            admin_emails = [e.strip() for e in settings.ADMIN_EMAIL.split(",") if e.strip()]
        
        service_name = getattr(instance.service, "name", "No Service")
        paid_time = instance.paid_at or instance.updated_at if hasattr(instance, "updated_at") else ""

        subject = f"ინვოისი #{instance.id} გადახდილია"
        body = (
            f"მომხმარებელი: {instance.user.email}\n"
            f"სერვისი: {service_name}\n"
            f"თანხა: {instance.amount}\n"
            f"გადახდის დრო: {paid_time}\n"
        )

        # 📨 მეილი ადმინს
        if admin_emails:
            try:
                send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, admin_emails, fail_silently=True)
            except Exception:
                pass

        # 📨 მეილი ინვოისის შემქმნელს
        try:
            send_mail(
                subject="თქვენი ინვოისი წარმატებით გადახდილია",
                message=(
                    f"გილოცავთ!\n\n"
                    f"თქვენი ინვოისი #{instance.id} გადახდილია და სერვისი გააქტიურდა.\n"
                    f"სერვისი: {service_name}\n"
                    f"თანხა: {instance.amount} ₾\n"
                    f"გადახდის დრო: {paid_time}\n\n"
                    "გმადლობთ რომ იყენებთ ჩვენს პლატფორმას."
                ),
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[instance.user.email],
                fail_silently=True
            )
        except Exception:
            pass



@receiver(post_save, sender=Application)
def notify_employer_on_new_application(sender, instance, created, **kwargs):
    if not created:
        return

    # ვაკანსია
    vacancy = instance.vacancy
    employer = vacancy.employer  # EmployerProfile
    employer_email = getattr(employer.user, "email", None)

    if not employer_email:
        return

    job_seeker = instance.job_seeker
    job_seeker_name = getattr(job_seeker, "username", job_seeker.email)

    subject = f"ახალი აპლიკაცია ვაკანსიაზე: {vacancy.title}"
    body = (
        f"გამომგზავნი: {job_seeker_name} ({job_seeker.email})\n"
        f"ვაკანსია: {vacancy.title}\n"
        f"ლოკაცია: {vacancy.location}\n"
        f"გაგზავნის დრო: {instance.applied_at:%Y-%m-%d %H:%M}\n\n"
        "გთხოვთ, შეამოწმოთ აპლიკაცია admin პანელში."
    )

    try:
        send_mail(
            subject,
            body,
            settings.DEFAULT_FROM_EMAIL,
            [employer_email],
            fail_silently=True
        )
    except Exception:
        pass

from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from .models import PurchasedService



@receiver(pre_save, sender=PurchasedService)
def notify_before_service_save(sender, instance, **kwargs):
    if not instance.pk:
        return  # ახალი ობიექტის შექმნისას გამოტოვე

    try:
        old = PurchasedService.objects.get(pk=instance.pk)
    except PurchasedService.DoesNotExist:
        return

    # პრემიუმ ლიმიტი: 1 → 0
    if old.remaining_premium > 0 and instance.remaining_premium == 0:
        subject = "💼 პრემიუმ განცხადებების ლიმიტი ამოიწურა"
        message = f"გამარჯობა {instance.user.get_full_name() or instance.user.email}, თქვენ ამოიწურეთ პრემიუმ განცხადებების ლიმიტი."
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [instance.user.email])

    # სტანდარტული ლიმიტი: 1 → 0
    if old.remaining_standard > 0 and instance.remaining_standard == 0:
        subject = "📋 სტანდარტული განცხადებების ლიმიტი ამოიწურა"
        message = f"გამარჯობა {instance.user.get_full_name() or instance.user.email}, თქვენ ამოიწურეთ სტანდარტული განცხადებების ლიმიტი."
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [instance.user.email])

    # ვადის გასვლა 
    if old.expiry_date and old.expiry_date >= timezone.now() and instance.expiry_date < timezone.now():
        subject = "⏰ სერვისის ვადა ამოიწურა"
        message = f"გამარჯობა {instance.user.get_full_name() or instance.user.email}, თქვენი სერვისი {instance.service.name} ამოიწურა."
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [instance.user.email])