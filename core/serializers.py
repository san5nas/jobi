import re
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from .models import (
    User, EmployerProfile, Vacancy, Application, Service, PurchasedService,
    Invoice, Category, JobSeekerProfile, Language, WorkExperience
)
from django.contrib.auth.password_validation import validate_password


class LanguageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Language
        fields = ['id', 'name']


class WorkExperienceSerializer(serializers.ModelSerializer):
    class Meta:
        model = WorkExperience
        fields = ['company_name', 'job_title', 'years_of_experience']


class JobSeekerProfileSerializer(serializers.ModelSerializer):
    languages = LanguageSerializer(many=True, required=False)
    work_experiences = WorkExperienceSerializer(many=True, required=False)

    class Meta:
        model = JobSeekerProfile
        fields = ['video_resume', 'education', 'diploma_upload', 'languages', 'work_experiences']


class EmployerProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmployerProfile
        fields = ['company_name', 'contact_person', 'is_approved_by_admin']


class UserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all(), message="ამ ელფოსტით მომხმარებელი უკვე არსებობს.")]
    )
    username = serializers.CharField(required=False, allow_blank=True)
    password = serializers.CharField(write_only=True)

    # პროფილები serialize-ისთვის, მაგრამ შექმნა serializer-ში აღარ მოხდება
    job_seeker_profile = JobSeekerProfileSerializer(required=False, read_only=True)
    employer_profile = EmployerProfileSerializer(required=False, read_only=True)

    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'user_type',
            'phone_number', 'password',
            'job_seeker_profile', 'employer_profile'
        ]

    def _generate_username_from_email(self, email: str) -> str:
        base = (email.split('@')[0] or 'user')[:150]  # AbstractUser.username max_length=150
        candidate = base
        i = 0
        while User.objects.filter(username=candidate).exists():
            i += 1
            suffix = f"_{i}"
            head = base[:150 - len(suffix)]
            candidate = f"{head}{suffix}"
        return candidate

    def validate_password(self, value):
        validate_password(value)
        return value

    def create(self, validated_data):
        # username email-იდან
        username = validated_data.get('username')
        email = validated_data.get('email')
        if not username or not username.strip():
            validated_data['username'] = self._generate_username_from_email(email)

        # ვქმნით User-ს
        user = User.objects.create_user(
            username=validated_data['username'],
            email=email,
            password=validated_data['password'],
            user_type=validated_data.get('user_type'),
            phone_number=validated_data.get('phone_number')
        )

        # ❌ აქ პროფილებს აღარ ვამატებთ
        # signals იზრუნებს JobSeekerProfile/EmployerProfile-ის შექმნაზე

        return user


class VacancySerializer(serializers.ModelSerializer):
    class Meta:
        model = Vacancy
        fields = '__all__'


class VacancyCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vacancy
        exclude = ['employer', 'published_date']


class ApplicationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Application
        fields = '__all__'


class ServiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Service
        fields = '__all__'


class PurchasedServiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = PurchasedService
        fields = '__all__'


class InvoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invoice
        fields = '__all__'


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = '__all__'


# ---- JWT Email Login Serializer ----
class EmailTokenObtainPairSerializer(TokenObtainPairSerializer):
    username_field = 'email'
