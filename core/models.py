from django.db import models
from django.contrib.auth.models import AbstractUser
from django.db.models import JSONField
from django.conf import settings
from django.utils import timezone
from django.utils.text import slugify
from django.contrib.auth.models import Group
from .validators import validate_cv_file, validate_video_file, validate_diploma_file



class User(AbstractUser):
    google_access_token = models.TextField(blank=True, null=True)
    google_refresh_token = models.TextField(blank=True, null=True)
    google_token_expiry = models.DateTimeField(blank=True, null=True)
    
    USER_TYPE_CHOICES = (
        ("admin", "ადმინისტრატორი"),
        ("job_seeker", "სამუშაოს მაძიებელი"),
        ("employer", "დამსაქმებელი"),
    )

    # აქ ვ.Overrideოთ მშობლის email ველი, რომ იყოს უნიკალური
    email = models.EmailField(unique=True)

    user_type = models.CharField(max_length=20, choices=USER_TYPE_CHOICES)
    phone_number = models.CharField(max_length=20, unique=True, blank=True, null=True)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    groups = models.ManyToManyField(
        'auth.Group',
        related_name='core_user_set',
        blank=True,
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='core_user_set',
        blank=True,
    )
    def save(self, *args, **kwargs):
        # რეგისტრაციის დროს თუ ახალია, მაშინ ვაუქმებთ is_staff ხელმისაწვდომობას
        if not self.pk:  # მხოლოდ შექმნისას
            if self.user_type == "job_seeker":
                self.is_staff = True
            elif self.user_type == "admin":
                self.is_staff = True
            elif self.user_type == "employer":
                self.is_staff = False
    
        super().save(*args, **kwargs)
    
        # ჯგუფების მიბმა — ეს შეიძლება დარჩეს
        group_map = {
            "job_seeker": "Jobseeker",
            "employer": "Employer",
            "admin": "Administrator",
        }
        group_name = group_map.get(self.user_type)
        if group_name:
            group, _ = Group.objects.get_or_create(name=group_name)
            self.groups.set([group])

    def __str__(self):
        return self.username
    
class AdminProfile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    phone = models.CharField(max_length=20, blank=True, null=True)

    def __str__(self):
        return f"Admin profile: {self.user.email}"

class EmployerProfile(models.Model):
    user = models.OneToOneField('User', on_delete=models.CASCADE, primary_key=True)
    company_name = models.CharField(max_length=255)
    contact_person = models.CharField(max_length=255)
    is_approved_by_admin = models.BooleanField(default=False)
    
    def __str__(self):
        return self.company_name

class JobSeekerProfile(models.Model):
    user = models.OneToOneField('User', on_delete=models.CASCADE, primary_key=True)

    cv = models.FileField(
        upload_to='cvs/', 
        blank=True, 
        null=True,
        validators=[validate_cv_file]   # ✅ ვალიდატორი
    )
    video_resume = models.FileField(
        upload_to='video_resumes/',
        blank=True,
        null=True,
        validators=[validate_video_file]   # ✅ ვალიდატორი
    )
    education = JSONField(blank=True, null=True)
    diploma_upload = models.FileField(
        upload_to='diplomas/',
        blank=True,
        null=True,
        validators=[validate_diploma_file]   # ✅ ვალიდატორი
    )
    languages = models.ManyToManyField('Language', through='JobSeekerLanguage', blank=True)
    skills    = models.ManyToManyField('Skill', blank=True)  


    preferred_categories = models.ManyToManyField("Category", blank=True)

    def __str__(self):
        return f"პროფილი: {self.user.username}"


class WorkExperience(models.Model):
    job_seeker_profile = models.ForeignKey(JobSeekerProfile, on_delete=models.CASCADE, related_name='work_experiences')
    company_name = models.CharField(max_length=255)
    job_title = models.CharField(max_length=255)
    years_of_experience = models.IntegerField()
    related_name="work_experiences"
    def __str__(self):
        return f"{self.job_title} at {self.company_name}"

class Language(models.Model):
    name = models.CharField(max_length=100, unique=True)
    
    def __str__(self):
        return self.name



class Category(models.Model):
    name = models.CharField(max_length=255, unique=True)
    slug = models.SlugField(unique=True, blank=True, null=True)

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name


class Vacancy(models.Model):
    VACANCY_TYPES = (
        ("full-time", "სრული განაკვეთი"),
        ("part-time", "ნახევარი განაკვეთი"),
        ("remote", "დისტანციური"),
    )

    employer = models.ForeignKey(EmployerProfile, on_delete=models.CASCADE, related_name='vacancies')
    title = models.CharField(max_length=255)
    description = models.TextField()
    requirements = models.TextField()
    min_salary = models.DecimalField(max_digits=10, decimal_places=2)
    location = models.CharField(max_length=255)
    vacancy_type = models.CharField(max_length=20, choices=VACANCY_TYPES)
    is_premium = models.BooleanField(default=False)
    is_published = models.BooleanField(default=False)
    is_approved = models.BooleanField(default=False)
    rejection_reason = models.TextField(blank=True, null=True)
    published_date = models.DateTimeField(auto_now_add=True)
    expiry_date = models.DateTimeField(blank=True, null=True)
    category = models.ForeignKey(Category, on_delete=models.SET_NULL, null=True, blank=True, related_name='vacancies')
    latitude = models.FloatField(null=True, blank=True)
    longitude = models.FloatField(null=True, blank=True)
    location_name = models.CharField(max_length=255, null=True, blank=True)


    def __str__(self):
        return self.title

    class Meta:
        permissions = (
            ("can_approve_vacancies", "Can approve vacancies"),
        )


class Application(models.Model):
    interview_event_id = models.CharField(max_length=128, blank=True, null=True)
    applied_at = models.DateTimeField(auto_now_add=True)

    APPLICATION_STATUSES = (
        ("new", "ახალი"),
        ("reviewed", "განხილული"),
        ("interview", "გასაუბრება"),
        ("hired", "აყვანილი"),
        ("rejected", "უარყოფილი"),
    )

    vacancy = models.ForeignKey(Vacancy, on_delete=models.CASCADE, related_name='applications')
    job_seeker = models.ForeignKey(User, on_delete=models.CASCADE)
    cv = models.CharField(max_length=500, blank=True, null=True)   # ⬅ მხოლოდ ლინკი
    cover_letter = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=20, choices=APPLICATION_STATUSES, default="new")

    interview_link = models.URLField(blank=True, null=True)
    interview_start = models.DateTimeField(blank=True, null=True)
    interview_end = models.DateTimeField(blank=True, null=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["job_seeker", "vacancy"],
                name="unique_application_per_jobseeker_vacancy"
            )
        ]

    def __str__(self):
        return f"განაცხადი '{self.vacancy.title}' | {self.job_seeker.username}"



class Service(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)

    # 🆕 ლიმიტები
    premium_limit = models.IntegerField(default=0)    #  პრემიუმის
    standard_limit = models.IntegerField(default=0)  # სტანდარტული განცხადების ლიმიტი
    duration_days = models.IntegerField(default=30)  # პაკეტის მოქმედების ვადა (დღეებში)

    def __str__(self):
        return self.name


class PurchasedService(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    service = models.ForeignKey(Service, on_delete=models.CASCADE)
    purchase_date = models.DateTimeField(auto_now_add=True)
    expiry_date = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=False)

    # 🆕 counters
    remaining_premium = models.IntegerField(default=0)
    remaining_standard = models.IntegerField(default=0)

    notified_expired = models.BooleanField(default=False)

    def activate(self):
        """გადახდის შემდეგ აქტივაცია (invoice → confirm)"""
        self.is_active = True
        self.expiry_date = timezone.now() + timezone.timedelta(days=self.service.duration_days)
        self.remaining_premium = self.service.premium_limit
        self.remaining_standard = self.service.standard_limit
        self.notified_expired = False  # ✅ ახალი პაკეტის აქტივაციაზე reset
        self.save()

    def __str__(self):
        return f"{self.user.username} - {self.service.name} ({'Active' if self.is_active else 'Inactive'})"

    
class Invoice(models.Model):
    STATUS_CHOICES = (
        ('unpaid', 'Unpaid'),
        ('paid', 'Paid'),
        ('cancelled', 'Cancelled'),
    )

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    service = models.ForeignKey(Service, on_delete=models.PROTECT, null=True, blank=True)
    amount = models.DecimalField(max_digits=8, decimal_places=2)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='unpaid')
    created_at = models.DateTimeField(auto_now_add=True)
    paid_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        service_name = self.service.name if self.service else "No Service"
        return f"{self.user.email} - {service_name} - {self.status}"

class MyVacancy(Vacancy):
    class Meta:
        proxy = True
        verbose_name = "my Vacancy"
        verbose_name_plural = "my Vacancy"

class Skill(models.Model):
    name = models.CharField(max_length=100, unique=True)
    def __str__(self): return self.name

LANGUAGE_LEVELS = (
    ("A1","A1"),("A2","A2"),("B1","B1"),("B2","B2"),("C1","C1"),("C2","C2"),
)

class JobSeekerLanguage(models.Model):
    profile  = models.ForeignKey('JobSeekerProfile', on_delete=models.CASCADE, related_name='language_items')
    language = models.ForeignKey('Language', on_delete=models.CASCADE)
    level    = models.CharField(max_length=2, choices=LANGUAGE_LEVELS, default="B1")

    class Meta:
        unique_together = ('profile','language')

    def __str__(self):
        return f"{self.profile.user} – {self.language} ({self.level})"

class Education(models.Model):
    profile   = models.ForeignKey(
        'JobSeekerProfile',
        on_delete=models.CASCADE,
        related_name='educations'   # ← ეს საკმარისია
    )
    institution = models.CharField(max_length=255)
    degree      = models.CharField(max_length=255, blank=True)
    field       = models.CharField(max_length=255, blank=True)
    start_date  = models.DateField(blank=True, null=True)
    end_date    = models.DateField(blank=True, null=True)
    currently_studying = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.institution} ({self.degree})"


class LanguageEntry(models.Model):
    profile = models.ForeignKey(
        JobSeekerProfile,
        on_delete=models.CASCADE,
        related_name='language_entries'
    )
    language = models.CharField(max_length=100)
    level = models.CharField(max_length=10, choices=LANGUAGE_LEVELS)

    def __str__(self):
        return f"{self.language} ({self.level})"


class SkillEntry(models.Model):
    profile = models.ForeignKey(
        JobSeekerProfile,
        on_delete=models.CASCADE,
        related_name='skill_entries'
    )
    skill = models.CharField(max_length=100)

    def __str__(self):
        return self.skill

class PreferredVacancy(Vacancy):
    class Meta:
        proxy = True
        verbose_name = "სასურველი ვაკანსია"
        verbose_name_plural = "სასურველი ვაკანსიები"

