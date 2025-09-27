import re
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from .models import (
    User, EmployerProfile, Vacancy, Application, Service, PurchasedService,
    Invoice, Category, JobSeekerProfile, Language, WorkExperience, AdminProfile, Skill,Education, LanguageEntry, SkillEntry
)
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from .models import User

from utils.email import send_password_reset_email

from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str

from .models import Test, TestResult


class SkillSerializer(serializers.ModelSerializer):
    class Meta:
        model = Skill
        fields = ("id", "name")

class WorkExperienceSerializer(serializers.ModelSerializer):
    class Meta:
        model = WorkExperience
        fields = ["id", "company_name", "job_title", "years_of_experience"]
        extra_kwargs = {
            "company_name": {"required": True},
            "job_title": {"required": True},
            "years_of_experience": {"required": True},
        }

    def create(self, validated_data):
        prof = self.context.get("profile")
        validated_data["job_seeker_profile"] = prof
        return super().create(validated_data)

    def update(self, instance, validated_data):
        # partial update ი გამოიყენება view-ში (partial=True), ამიტომ OKა
        return super().update(instance, validated_data)

class WorkExperienceUpsertListSerializer(serializers.Serializer):
    items = WorkExperienceSerializer(many=True)

    def validate_items(self, value):
        if not isinstance(value, list):
            raise serializers.ValidationError("items must be a list")
        if len(value) == 0:
            raise serializers.ValidationError("items list cannot be empty")
        return value

class SkillCreateByNameSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=100)



class EducationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Education
        fields = [
            "id",
            "institution",
            "degree",
            "field",
            "start_date",
            "end_date",
            "currently_studying"
        ]


class LanguageEntrySerializer(serializers.ModelSerializer):
    class Meta:
        model = LanguageEntry
        fields = [
            "id",
            "language",
            "level",
        ]

class EducationBulkSerializer(serializers.Serializer):
    items = EducationSerializer(many=True)

    def validate_items(self, value):
        if not value:
            raise serializers.ValidationError("Items list cannot be empty")
        return value


class SkillEntrySerializer(serializers.ModelSerializer):
    class Meta:
        model = SkillEntry
        fields = [
            "id",
            "skill",
        ]

class SkillEntryBulkSerializer(serializers.Serializer):
    items = SkillEntrySerializer(many=True)

    def validate_items(self, value):
        if not value:
            raise serializers.ValidationError("Items list cannot be empty")
        return value


class LanguageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Language
        fields = ['id', 'name']

class LanguageEntrySerializer(serializers.ModelSerializer):
    class Meta:
        model = LanguageEntry
        fields = [
            "id",
            "language",
            "level",
        ]

class LanguagesUpsertSerializer(serializers.Serializer):
    items = LanguageEntrySerializer(many=True)

    def validate_items(self, value):
        if not isinstance(value, list):
            raise serializers.ValidationError("items must be a list")
        return value

class JobSeekerProfileSerializer(serializers.ModelSerializer):
    work_experiences = WorkExperienceSerializer(many=True, source="workexperience_set", read_only=True)
    education_entries = EducationSerializer(many=True, source="education_set", read_only=True)
    language_entries = LanguageEntrySerializer(many=True, source="languageentry_set", read_only=True)
    skill_entries = SkillEntrySerializer(many=True, source="skillentry_set", read_only=True)
    profile_image = serializers.ImageField(required=False, allow_null=True)

    preferred_categories = serializers.PrimaryKeyRelatedField(
        many=True, queryset=Category.objects.all(), required=False
    )

    class Meta:
        model = JobSeekerProfile
        fields = (
            "id",
            "cv",
            "video_resume",
            "diploma_upload",
            "preferred_categories",
            "work_experiences",
            "education_entries",
            "language_entries",
            "skill_entries",
            "profile_image"
        )


class MyJobSeekerProfileSerializer(serializers.ModelSerializer):
    user_id = serializers.IntegerField(source="user.id", read_only=True)
    username = serializers.CharField(source="user.username", read_only=True)
    email = serializers.EmailField(source="user.email", read_only=True)

    work_experiences = WorkExperienceSerializer(many=True, required=False)
    education_entries = EducationSerializer(many=True, required=False, source="educations")
    language_entries = LanguageEntrySerializer(many=True, required=False)
    skill_entries = SkillEntrySerializer(many=True, required=False)
    profile_image = serializers.ImageField(required=False, allow_null=True, use_url=True)

    class Meta:
        model = JobSeekerProfile
        fields = [
            "user_id", "username", "email",
            "cv", "video_resume", "diploma_upload",
            "profile_image",
            "preferred_categories",
            "work_experiences",
            "education_entries",
            "language_entries",
            "skill_entries",
            
        ]

    def update(self, instance, validated_data):
        education_data = validated_data.pop("educations", [])
        language_data = validated_data.pop("language_entries", [])
        skill_data = validated_data.pop("skill_entries", [])
        work_exp_data = validated_data.pop("work_experiences", [])
    
        # --- მოვუაროთ ჩვეულებრივ ველებს ---
        for attr, value in validated_data.items():
            if attr == "preferred_categories":
                # M2M append → უბრალოდ დაამატებს ახალს, არ წაშლის ძველს
                instance.preferred_categories.add(*value)
            else:
                setattr(instance, attr, value)
        instance.save()
    
        # --- Nested append ლოგიკა ---
        for item in education_data:
            Education.objects.create(profile=instance, **item)
    
        for item in language_data:
            LanguageEntry.objects.create(profile=instance, **item)
    
        for item in skill_data:
            SkillEntry.objects.create(profile=instance, **item)
    
        for item in work_exp_data:
            WorkExperience.objects.create(job_seeker_profile=instance, **item)
    
        return instance
    
    

class JobSeekerProfilePublicSerializer(serializers.ModelSerializer):
    user_id = serializers.IntegerField(source="user.id", read_only=True)
    education_entries = EducationSerializer(many=True, source="educations", read_only=True)
    language_entries = LanguageEntrySerializer(many=True, read_only=True)
    skill_entries = SkillEntrySerializer(many=True, read_only=True)

    class Meta:
        model = JobSeekerProfile
        fields = [
            "user_id",
            "cv",
            "video_resume",
            "diploma_upload",
            "preferred_categories",
            "education_entries",
            "language_entries",
            "skill_entries",
        ]

class JobSeekerProfilePrivateSerializer(serializers.ModelSerializer):
    class Meta:
        model = JobSeekerProfile
        # საკუთარი პროფილის ნახვისას სრული ველები
        fields = "__all__"

class EmployerProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmployerProfile
        fields = "__all__"
class EmployerProfileNestedSerializer(serializers.ModelSerializer):
    company_id_number = serializers.CharField(required=True, allow_blank=False)
    class Meta:
        model = EmployerProfile
        fields = ["company_name", "contact_person", "phone_number","company_id_number"]
# ---------- User serializer ----------
class UserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(
            queryset=User.objects.all(),
            message="ამ ელფოსტით მომხმარებელი უკვე არსებობს."
        )]
    )
    username = serializers.CharField(required=False, allow_blank=True)
    password = serializers.CharField(write_only=True)

    full_name = serializers.CharField(required=False, allow_blank=False)

    job_seeker_profile = JobSeekerProfileSerializer(read_only=True)
    employer_profile = EmployerProfileNestedSerializer(required=False)

    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'user_type',
            'phone_number', 'password', 'full_name',
            'job_seeker_profile', 'employer_profile'
        ]
        extra_kwargs = {"password": {"write_only": True}}

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

    def validate(self, attrs):
        """
        სავალდებულო ველები რეგისტრაციისას:
        - job_seeker → full_name
        - employer → employer_profile.company_id_number
        """
        data = self.initial_data or {}
        user_type = data.get('user_type')

        if user_type == 'job_seeker':
            fn = (data.get('full_name') or '').strip()
            if not fn or ' ' not in fn:
                raise serializers.ValidationError({
                    'full_name': 'გთხოვთ შეიყვანოთ სრული სახელი (სახელი და გვარი), მაგ: "Aleksandre Goguadze".'
                })

        if user_type == 'employer':
            ep = data.get('employer_profile') or {}
            if not ep.get('company_id_number'):
                raise serializers.ValidationError({
                    'employer_profile.company_id_number': 'სავალდებულოა კომპანიის საიდენტიფიკაციო კოდი.'
                })

        return attrs

    def create(self, validated_data):
        employer_profile_data = self.initial_data.get("employer_profile", None)

        username = validated_data.get('username')
        email = validated_data.get('email')
        if not username or not username.strip():
            validated_data['username'] = self._generate_username_from_email(email)

        # User
        user = User.objects.create_user(
            username=validated_data['username'],
            email=email,
            password=validated_data['password'],
            user_type=validated_data.get('user_type'),
            phone_number=validated_data.get('phone_number'),
            full_name=(self.initial_data.get('full_name') or '').strip()  # ➕ save full_name
        )

        # EmployerProfile
        if user.user_type == "employer" and employer_profile_data:
            EmployerProfile.objects.update_or_create(
                user=user,
                defaults={
                    "company_name": employer_profile_data.get("company_name", ""),
                    "contact_person": employer_profile_data.get("contact_person", user.username),
                    "phone_number": employer_profile_data.get("phone_number") or user.phone_number,
                    "company_id_number": employer_profile_data.get("company_id_number"),  # ➕ save company_id_number
                }
            )

        # JobSeekerProfile
        if user.user_type == "job_seeker":
            JobSeekerProfile.objects.get_or_create(user=user)

        return User.objects.select_related("employerprofile", "jobseekerprofile").get(id=user.id)


class VacancySerializer(serializers.ModelSerializer):
    class Meta:
        model = Vacancy
        fields = [
            "id", "title", "description", "requirements",
            "min_salary", "location", "location_name",
            "latitude", "longitude",
            "vacancy_type", "is_premium", "is_published", "is_approved",
            "published_date", "expiry_date",
            "category", "employer"
        ]

class VacancyCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vacancy
        exclude = ['employer', 'published_date']

class ApplicationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Application
        fields = '__all__'
        read_only_fields = ('job_seeker',)

    def create(self, validated_data):
        request = self.context.get('request')
        if not request or not request.user or not request.user.is_authenticated:
            raise serializers.ValidationError("Authentication required.")

        validated_data['job_seeker'] = request.user

        # Duplicate check (ბაზის დარტყმის წინ)
        if Application.objects.filter(
            job_seeker=request.user,
            vacancy=validated_data.get('vacancy')
        ).exists():
            raise serializers.ValidationError(
                "ამ ვაკანსიაზე განაცხადი უკვე გაგზავნილია."
            )

        return super().create(validated_data)

class ServiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Service
        fields = '__all__'

class PurchasedServiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = PurchasedService
        fields = '__all__'

class InvoiceSerializer(serializers.ModelSerializer):
    invoice_id = serializers.IntegerField(source="id", read_only=True)
    user_id = serializers.IntegerField(source="user.id", read_only=True)
    user_email = serializers.EmailField(source="user.email", read_only=True)

    class Meta:
        model = Invoice
        fields = ["invoice_id", "amount", "status", "service", "user_id", "user_email"]

class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = '__all__'
# ---- JWT Email Login Serializer ----
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework import serializers
from .models import User  # 👈 შენი custom User მოდელი

class EmailTokenObtainPairSerializer(TokenObtainPairSerializer):
    # ვუთხრათ, რომ username_field არის email
    username_field = "email"

    def validate(self, attrs):
        data = super().validate(attrs)

        if not self.user.is_verified:
            raise serializers.ValidationError("გთხოვთ, დაადასტუროთ თქვენი ელფოსტა.")

        # 🔑 Custom payload
        data.update({
            "email": self.user.email,
            "user_type": self.user.user_type,
            "profile_image": (
                self.user.jobseekerprofile.profile_image.url
                if hasattr(self.user, "jobseekerprofile") and self.user.jobseekerprofile.profile_image
                else (
                    self.user.employerprofile.profile_image.url
                    if hasattr(self.user, "employerprofile") and self.user.employerprofile.profile_image
                    else None
                )
            )
        })
        return data

class AdminProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = AdminProfile
        fields = '__all__'

class RequestPasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("მომხმარებელი ასეთი ელფოსტით არ მოიძებნა.")
        return value

    def save(self):
        email = self.validated_data["email"]
        user = User.objects.get(email=email)

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)

        reset_link = f"https://jobify.ge/reset-password-confirm/?uid={uid}&token={token}"

        context = {
            "subject": "პაროლის აღდგენა",
            "to": [user.email],
            "template_name": "emails/password_reset.html",  # თუ გაქვს html template
            "context": {
                "user": user,
                "reset_link": reset_link
            },
        }
        send_password_reset_email(**context)

class PasswordResetConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True)
    confirm_new_password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        try:
            uid = force_str(urlsafe_base64_decode(attrs['uid']))
            user = User.objects.get(pk=uid)
        except (User.DoesNotExist, ValueError, TypeError, OverflowError):
            raise serializers.ValidationError({"uid": "მომხმარებელი ვერ მოიძებნა."})

        if not default_token_generator.check_token(user, attrs["token"]):
            raise serializers.ValidationError({"token": "ტოკენი არასწორია ან ვადაგასულია."})

        if attrs["new_password"] != attrs["confirm_new_password"]:
            raise serializers.ValidationError({"confirm_new_password": "პაროლები არ ემთხვევა."})

        self.user = user
        return attrs

    def save(self):
        self.user.set_password(self.validated_data["new_password"])
        self.user.save()



class TestSerializer(serializers.ModelSerializer):
    class Meta:
        model = Test
        fields = ["id", "vacancy", "employer", "form_id", "title", "created_at"]
        read_only_fields = ["id", "created_at", "employer"]

    def create(self, validated_data):
        request = self.context.get("request")
        if request and hasattr(request, "user"):
            validated_data["employer"] = request.user
        return super().create(validated_data)


class TestResultSerializer(serializers.ModelSerializer):
    applicant_email = serializers.EmailField(
        source="application.job_seeker.email", read_only=True
    )

    class Meta:
        model = TestResult
        fields = (
            "id",
            "test",
            "application",
            "respondent_email",
            "response_id",
            "answers",
            "total_score",
            "submitted_at",
            "applicant_email",          # ← დაამატე აქ
        )
        read_only_fields = ["id", "submitted_at", "applicant_email"]
        extra_kwargs = {
            "application": {"allow_null": True, "required": False}  # ← სურვილისამებრ, უსაფრთხოდ
        }

