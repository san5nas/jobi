from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.core.mail import send_mail
from django.conf import settings
from .models import User, Invoice, JobSeekerProfile, EmployerProfile, AdminProfile, Vacancy
from django.core.signing import TimestampSigner
from django.utils import timezone
from utils.email import send_verification_email
from .models import PurchasedService, Application  

from django.db.models import Q


signer = TimestampSigner()


def get_admin_emails():
    """ყველა იმეილი ვინც არის Administrator ჯგუფში ან superuser."""
    admin_users = User.objects.filter(
        Q(is_superuser=True) | Q(groups__name="Administrator"),
        is_active=True,
        email__isnull=False
    ).distinct()
    return [u.email for u in admin_users if u.email]


# --- User signals ---

@receiver(post_save, sender=User)
def send_verification_on_register(sender, instance, created, **kwargs):
    if created and instance.email:
        token = signer.sign(instance.pk)
        send_verification_email(instance, token)


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


# --- EmployerProfile signals ---

@receiver(pre_save, sender=EmployerProfile)
def cache_old_approval_status(sender, instance, **kwargs):
    if instance.pk:
        try:
            old = EmployerProfile.objects.only("is_approved_by_admin").get(pk=instance.pk)
            instance._old_is_approved = old.is_approved_by_admin
        except EmployerProfile.DoesNotExist:
            instance._old_is_approved = None
    else:
        instance._old_is_approved = None


@receiver(post_save, sender=EmployerProfile)
def notify_admin_on_employer_created(sender, instance, created, **kwargs):
    admin_emails = get_admin_emails()
    if not admin_emails and not instance.user.email:
        return


    if created:
        if admin_emails:
            subject = "New employer registered"
            message_lines = [
                f"Username: {instance.user.username}",
                f"Email: {instance.user.email}",
                f"User type: {instance.user.user_type}",
                f"Company: {instance.company_name or 'Not provided'}",
                f"Company ID: {getattr(instance, 'company_id_number', 'Not provided')}",
                f"Contact person: {instance.contact_person or 'Not provided'}",
                f"Phone: {getattr(instance, 'phone_number', 'Not provided')}",
                f"Approved by admin: {instance.is_approved_by_admin}",
            ]
            try:
                send_mail(subject, "\n".join(message_lines), settings.DEFAULT_FROM_EMAIL, admin_emails, fail_silently=True)
            except Exception:
                pass
        return

 
    if getattr(instance, "_old_is_approved", None) is False and instance.is_approved_by_admin is True:
        now_str = timezone.now().strftime("%Y-%m-%d %H:%M")
        approver = getattr(instance, "approved_by", None)
        approver_info = approver.email if approver else "უცნობია"

        # Admin-ებზე
        if admin_emails:
            subject = f"✅ დამსაქმებელი დამტკიცდა: {instance.company_name}"
            message_lines = [
                f"დამტკიცდა: {instance.company_name}",
                f"საკონტაქტო პირი: {instance.contact_person}",
                f"დრო: {now_str}",
                f"მომხმარებელი: {instance.user.email}",
                f"დამამტკიცებელი: {approver_info}",
            ]
            try:
                send_mail(subject, "\n".join(message_lines), settings.DEFAULT_FROM_EMAIL, admin_emails, fail_silently=True)
            except Exception:
                pass

        # თვითონ დამსაქმებელზე
        subject_user = "✅ თქვენი პროფილი დამტკიცდა"
        message_user = (
            f"გამარჯობა {instance.user.username},\n\n"
            "გილოცავთ! თქვენი დამსაქმებლის პროფილი ადმინისტრატორმა დაამტკიცა.\n\n"
            f"კომპანია: {instance.company_name}\n"
            f"საკონტაქტო პირი: {instance.contact_person}\n\n"
            "ახლა შეგიძლიათ სრულად გამოიყენოთ ჩვენი პლატფორმის ფუნქციონალი."
        )
        try:
            send_mail(subject_user, message_user, settings.DEFAULT_FROM_EMAIL, [instance.user.email], fail_silently=True)
        except Exception:
            pass


# --- Vacancy signals ---

@receiver(post_save, sender=Vacancy)
def notify_admin_on_new_vacancy(sender, instance, created, **kwargs):
    if not created:
        return
    admin_emails = get_admin_emails()
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


# --- Invoice signals ---

@receiver(post_save, sender=Invoice)
def notify_admin_on_invoice_created(sender, instance, created, **kwargs):
    if not created:
        return

    admin_emails = get_admin_emails()
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
        admin_emails = get_admin_emails()
        service_name = getattr(instance.service, "name", "No Service")
        paid_time = instance.paid_at or instance.updated_at if hasattr(instance, "updated_at") else ""

        subject = f"ინვოისი #{instance.id} გადახდილია"
        body = (
            f"მომხმარებელი: {instance.user.email}\n"
            f"სერვისი: {service_name}\n"
            f"თანხა: {instance.amount}\n"
            f"გადახდის დრო: {paid_time}\n"
        )

        if admin_emails:
            try:
                send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, admin_emails, fail_silently=True)
            except Exception:
                pass

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


# --- Application signals ---

@receiver(post_save, sender=Application)
def notify_employer_on_new_application(sender, instance, created, **kwargs):
    if not created:
        return

    vacancy = instance.vacancy
    employer = vacancy.employer
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
        send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, [employer_email], fail_silently=True)
    except Exception:
        pass


# --- PurchasedService signals ---

@receiver(pre_save, sender=PurchasedService)
def notify_before_service_save(sender, instance, **kwargs):
    if not instance.pk:
        return

    try:
        old = PurchasedService.objects.get(pk=instance.pk)
    except PurchasedService.DoesNotExist:
        return

    if old.remaining_premium > 0 and instance.remaining_premium == 0:
        subject = "💼 პრემიუმ განცხადებების ლიმიტი ამოიწურა"
        message = f"გამარჯობა {instance.user.get_full_name() or instance.user.email}, თქვენ ამოიწურეთ პრემიუმ განცხადებების ლიმიტი."
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [instance.user.email])

    if old.remaining_standard > 0 and instance.remaining_standard == 0:
        subject = "📋 სტანდარტული განცხადებების ლიმიტი ამოიწურა"
        message = f"გამარჯობა {instance.user.get_full_name() or instance.user.email}, თქვენ ამოიწურეთ სტანდარტული განცხადებების ლიმიტი."
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [instance.user.email])

    if old.expiry_date and old.expiry_date >= timezone.now() and instance.expiry_date < timezone.now():
        subject = "⏰ სერვისის ვადა ამოიწურა"
        message = f"გამარჯობა {instance.user.get_full_name() or instance.user.email}, თქვენი სერვისი {instance.service.name} ამოიწურა."
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [instance.user.email])
