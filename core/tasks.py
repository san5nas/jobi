from celery import shared_task
from django.utils import timezone
from core.models import Vacancy, PurchasedService

@shared_task
def deactivate_expired_vacancies():
    """Deactivate vacancies whose expiry_date has passed"""
    now = timezone.now()
    expired = Vacancy.objects.filter(
        is_published=True,
        expiry_date__lt=now
    )
    count = expired.update(is_published=False)
    return f"{count} vacancies deactivated."


@shared_task
def deactivate_expired_services():
    """Deactivate PurchasedServices whose expiry_date has passed"""
    now = timezone.now()
    expired = PurchasedService.objects.filter(
        is_active=True,
        expiry_date__lt=now
    )
    count = expired.update(is_active=False)
    return f"{count} services deactivated."
