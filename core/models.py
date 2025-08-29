from django.db import models
from django.contrib.auth.models import AbstractUser
from django.db.models import JSONField
from django.conf import settings

class User(AbstractUser):
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
    is_active = models.BooleanField(default=False) 

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
    video_resume = models.FileField(upload_to='video_resumes/', blank=True, null=True)
    education = JSONField(blank=True, null=True)
    diploma_upload = models.FileField(upload_to='diplomas/', blank=True, null=True)
    languages = models.ManyToManyField('Language', blank=True)

    def __str__(self):
        return f"პროფილი: {self.user.username}"

class WorkExperience(models.Model):
    job_seeker_profile = models.ForeignKey(JobSeekerProfile, on_delete=models.CASCADE, related_name='work_experiences')
    company_name = models.CharField(max_length=255)
    job_title = models.CharField(max_length=255)
    years_of_experience = models.IntegerField()
    
    def __str__(self):
        return f"{self.job_title} at {self.company_name}"

class Language(models.Model):
    name = models.CharField(max_length=100, unique=True)
    
    def __str__(self):
        return self.name

class Category(models.Model):
    name = models.CharField(max_length=100, unique=True)
    
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
    published_date = models.DateTimeField(auto_now_add=True)
    expiry_date = models.DateTimeField(blank=True, null=True)
    category = models.ForeignKey(Category, on_delete=models.SET_NULL, null=True, blank=True, related_name='vacancies')
    
    def __str__(self):
        return self.title

class Application(models.Model):
    APPLICATION_STATUSES = (
        ("new", "ახალი"),
        ("reviewed", "განხილული"),
        ("interview", "გასაუბრება"),
        ("hired", "აყვანილი"),
        ("rejected", "უარყოფილი"),
    )
    vacancy = models.ForeignKey(Vacancy, on_delete=models.CASCADE, related_name='applications')
    job_seeker = models.ForeignKey(User, on_delete=models.CASCADE)
    cv = models.FileField(upload_to='cvs/')
    cover_letter = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=20, choices=APPLICATION_STATUSES, default="new")
    applied_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"განაცხადი ვაკანსიაზე '{self.vacancy.title}' მომხმარებლისგან '{self.job_seeker.username}'"

class Service(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    
    def __str__(self):
        return self.name

class PurchasedService(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    service = models.ForeignKey(Service, on_delete=models.CASCADE)
    purchase_date = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=False)
    expiry_date = models.DateTimeField(null=True, blank=True)
    
    def __str__(self):
        return f"{self.user.username} - {self.service.name}"
    
class Invoice(models.Model):
    invoice_number = models.CharField(max_length=20, unique=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    is_paid = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.invoice_number
