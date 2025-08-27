from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from .models import User, JobSeekerProfile, EmployerProfile, AdminProfile

# შევინახოთ ძველი user_type pre_save-ში, რომ შევადაროთ post_save-ში
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

@receiver(post_save, sender=User)
def ensure_profile_for_user_type(sender, instance, created, **kwargs):
    # თუ user_type ცარიელია, არაფერს ვაკეთებთ
    if not instance.user_type:
        return

    # ერთ დროს ერთი ტიპის პროფილი გვქონდეს – დანარჩენს წავშლით
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
