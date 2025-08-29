import re
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from .models import (
    User, EmployerProfile, Vacancy, Application, Service, PurchasedService,
    Invoice, Category, JobSeekerProfile, Language, WorkExperience
)

# ---------- Nested serializers ----------

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

    def create(self, validated_data):
        languages_data = validated_data.pop('languages', [])
        work_experiences_data = validated_data.pop('work_experiences', [])
        job_seeker_profile = JobSeekerProfile.objects.create(**validated_data)

        for lang_data in languages_data:
            language, _ = Language.objects.get_or_create(name=lang_data['name'])
            job_seeker_profile.languages.add(language)

        for experience_data in work_experiences_data:
            WorkExperience.objects.create(job_seeker_profile=job_seeker_profile, **experience_data)

        return job_seeker_profile


class EmployerProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmployerProfile
        fields = ['company_name', 'contact_person', 'is_approved_by_admin']


# ---------- User serializer ----------

class UserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all(), message="ამ ელფოსტით მომხმარებელი უკვე არსებობს.")]
    )
    username = serializers.CharField(required=False, allow_blank=True)
    password = serializers.CharField(write_only=True)
    job_seeker_profile = JobSeekerProfileSerializer(required=False)
    employer_profile = EmployerProfileSerializer(required=False)

    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'user_type',
            'phone_number', 'password',
            'job_seeker_profile', 'employer_profile'
        ]

    def _generate_username_from_email(self, email: str) -> str:
        base = (email.split('@')[0] or 'user')[:150]
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
        """
        მნიშვნელოვანი: თუ სადმე signals / post_save ავტომატურად ქმნის პროფილებს,
        აქ დამატებით აღარ ვქმნით. ვაკეთებთ მხოლოდ get_or_create-ს, რომ
        UNIQUE constraint შეცდომა არ მივიღოთ.
        """
        job_seeker_profile_data = validated_data.pop('job_seeker_profile', None)
        employer_profile_data = validated_data.pop('employer_profile', None)

        username = validated_data.get('username')
        email = validated_data.get('email')
        if not username or not username.strip():
            validated_data['username'] = self._generate_username_from_email(email)

        # მომხმარებელი
        user = User.objects.create_user(
            username=validated_data['username'],
            email=email,
            password=validated_data['password'],
            user_type=validated_data.get('user_type'),
            phone_number=validated_data.get('phone_number')
        )

        # პროფილები — მხოლოდ შესაბამისი ტიპისთვის და უსაფრთხოდ
        if user.user_type == 'job_seeker':
            profile, _ = JobSeekerProfile.objects.get_or_create(user=user)
            if job_seeker_profile_data:
                languages_data = job_seeker_profile_data.pop('languages', [])
                work_experiences_data = job_seeker_profile_data.pop('work_experiences', [])

                # განახლება/შევსება
                for key, val in job_seeker_profile_data.items():
                    setattr(profile, key, val)
                profile.save()

                for lang_data in languages_data:
                    language, _ = Language.objects.get_or_create(name=lang_data['name'])
                    profile.languages.add(language)
                for experience_data in work_experiences_data:
                    WorkExperience.objects.create(job_seeker_profile=profile, **experience_data)

        elif user.user_type == 'employer':
            profile, created = EmployerProfile.objects.get_or_create(user=user)
            if employer_profile_data:
                for key, val in employer_profile_data.items():
                    setattr(profile, key, val)
                profile.save()

        # სხვა ტიპებისთვის არაფერი დამატებითი
        return user


# ---------- Business models serializers ----------

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
    # SimpleJWT-ს ვუთხრათ, რომ username-ის ნაცვლად email გამოიყენოს
    username_field = 'email'
