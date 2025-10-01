import requests   
from django.shortcuts import get_object_or_404, render, redirect
from django.http import HttpResponse
from django.template.loader import render_to_string
from django.views.decorators.csrf import csrf_exempt

from rest_framework.decorators import action, api_view
from rest_framework import generics, permissions, status
from rest_framework.response import Response

from rest_framework.exceptions import PermissionDenied

from rest_framework.permissions import AllowAny

from django.utils import timezone
from django.contrib.auth import authenticate, login
from django.core.mail import send_mail
from django.conf import settings

from rest_framework import viewsets
import jwt

from rest_framework.views import APIView
from django.contrib.auth.password_validation import validate_password
from rest_framework.exceptions import ValidationError


from .models import (
    User, Vacancy, Application, EmployerProfile, Category, Invoice,
    JobSeekerProfile, Language, AdminProfile, Service, PurchasedService,Skill, WorkExperience, 
    Test, TestResult,
)
from .serializers import (
    UserSerializer,
    VacancySerializer,
    ApplicationSerializer,
    VacancyCreateSerializer,
    CategorySerializer,
    JobSeekerProfileSerializer,
    LanguageSerializer,
    EmployerProfileSerializer,
    EmailTokenObtainPairSerializer,
    InvoiceSerializer,
    AdminProfileSerializer,
    ServiceSerializer,
    PurchasedServiceSerializer,
    WorkExperienceSerializer,
    WorkExperienceUpsertListSerializer,
    SkillSerializer,
    SkillCreateByNameSerializer,
    JobSeekerProfilePrivateSerializer,
    JobSeekerProfilePublicSerializer,
    MyJobSeekerProfileSerializer,
    EducationSerializer,
    Education,
    EducationBulkSerializer,
    LanguageEntrySerializer,
    LanguageEntry,
    SkillEntrySerializer,
    SkillEntry,
    SkillEntryBulkSerializer,
    TestSerializer,
    TestResultSerializer,
)


from utils.google import create_google_form, get_form_responses,create_form_with_items
from django.utils.dateparse import parse_datetime

from .filters import JobSeekerProfileFilter
from django_filters.rest_framework import DjangoFilterBackend


from .permissions import IsEmployer, IsAdmin, IsJobSeeker, CanEditVacancy, CanUpdateApplicationStatus
from utils.email import send_verification_email

from rest_framework.permissions import IsAuthenticated
from .permissions import ReadOnlyOrRole
# --- JWT email login view ---
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken



from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from .models import MyVacancy
from django.http import JsonResponse, HttpResponseBadRequest


from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from django.core.signing import BadSignature, SignatureExpired, TimestampSigner

from django.db import models
from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters
from .filters import VacancyFilter

from rest_framework_simplejwt.views import TokenRefreshView

from rest_framework_simplejwt.exceptions import InvalidToken


from .utils.user_profile import get_user_profile_info

from .models import PasswordResetPin

signer = TimestampSigner()
User = get_user_model()

@csrf_exempt
def verify_email_view(request):
    token = request.GET.get("token")
    if not token:
        return HttpResponseBadRequest("Missing token")

    try:
        user_id = signer.unsign(token, max_age=60*60*24)  # 24h
        user = User.objects.get(pk=user_id)
        user.is_verified = True
        user.save(update_fields=["is_verified"])
        return JsonResponse({"detail": "Email verified ✅"})
    except (BadSignature, SignatureExpired, User.DoesNotExist):
        return HttpResponseBadRequest("Invalid or expired token")

@api_view(["GET", "POST"])
def google_login_url(request):
    client_id = settings.GOOGLE_CLIENT_ID
    redirect_uri = settings.GOOGLE_LOGIN_REDIRECT
    scope = "openid email profile"

    auth_url = (
        "https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={client_id}"
        f"&redirect_uri={redirect_uri}"
        f"&response_type=code"
        f"&scope={scope}"
        f"&access_type=offline"
        f"&prompt=consent"
    )
    return Response({"url": auth_url})

@api_view(["POST"])
def google_login_callback_json(request):
    code = request.data.get("code") or request.GET.get("code")
    if not code:
        return Response({"error": "Missing code"}, status=status.HTTP_400_BAD_REQUEST)

    # აქ შენი GOOGLE_CLIENT_ID და SECRET
    client_id = settings.GOOGLE_CLIENT_ID
    client_secret = settings.GOOGLE_CLIENT_SECRET
    redirect_uri = settings.GOOGLE_LOGIN_REDIRECT

    # Step 1: exchange code for token
    token_url = "https://oauth2.googleapis.com/token"
    token_data = {
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }
    token_r = requests.post(token_url, data=token_data)
    token_json = token_r.json()

    if "error" in token_json:
        return Response(token_json, status=status.HTTP_400_BAD_REQUEST)

    access_token = token_json.get("access_token")

    # Step 2: get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v2/userinfo"
    userinfo_r = requests.get(userinfo_url, headers={"Authorization": f"Bearer {access_token}"})
    userinfo = userinfo_r.json()

    # აქ შეგიძლია user შექმნა/შესვლა JWT ტოკენებით
    email = userinfo.get("email")
    name = userinfo.get("name")

    user, created = User.objects.get_or_create(email=email, defaults={"username": email.split("@")[0]})

    # JWT გენერაცია
    refresh = RefreshToken.for_user(user)
    return Response({
        "user": {
            "id": user.id,
            "email": user.email,
            "username": user.username,
        },
        "tokens": {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
        }
    })

def _my_profile(user):
    return get_object_or_404(JobSeekerProfile, user=user)


class MyProfileViewSet(viewsets.ViewSet):
    permission_classes = [permissions.IsAuthenticated]

    def _profile(self, request):
        return get_object_or_404(JobSeekerProfile, user=request.user)

    # -------- PROFILE --------
    def list(self, request):
        prof = self._profile(request)
        ser = MyJobSeekerProfileSerializer(prof, context={"request": request})
        return Response(ser.data)

    @action(detail=False, methods=["patch"], url_path="update")
    def update_self(self, request):
        print("FILES:", request.FILES)
        prof = self._profile(request)
        ser = MyJobSeekerProfileSerializer(
            prof, data=request.data, partial=True, context={"request": request}
        )
        ser.is_valid(raise_exception=True)
        ser.save()
        return Response(ser.data)

    # -------- WORK EXPERIENCE --------
    @action(detail=False, methods=["post"], url_path="work-experiences")
    def add_work_experience(self, request):
        prof = self._profile(request)
        ser = WorkExperienceSerializer(data=request.data, context={"profile": prof})
        ser.is_valid(raise_exception=True)
        obj = ser.save()
        return Response(WorkExperienceSerializer(obj).data, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=["patch"], url_path=r"work-experiences/(?P<pk>\d+)")
    def update_work_experience(self, request, pk=None):
        prof = self._profile(request)
        obj = get_object_or_404(WorkExperience, pk=pk, job_seeker_profile=prof)
        ser = WorkExperienceSerializer(obj, data=request.data, partial=True, context={"profile": prof})
        ser.is_valid(raise_exception=True)
        obj = ser.save()
        return Response(WorkExperienceSerializer(obj).data)

    @action(detail=False, methods=["delete"], url_path=r"work-experiences/(?P<pk>\d+)")
    def delete_work_experience(self, request, pk=None):
        prof = self._profile(request)
        obj = get_object_or_404(WorkExperience, pk=pk, job_seeker_profile=prof)
        obj.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=False, methods=["patch"], url_path="work-experiences/bulk")
    def bulk_upsert_work_experiences(self, request):
        prof = self._profile(request)
        ser = WorkExperienceUpsertListSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        created_or_updated = []
        for item in ser.validated_data["items"]:
            if item.get("id"):
                obj = get_object_or_404(WorkExperience, pk=item["id"], job_seeker_profile=prof)
                s = WorkExperienceSerializer(obj, data=item, partial=True, context={"profile": prof})
                s.is_valid(raise_exception=True)
                created_or_updated.append(s.save())
            else:
                s = WorkExperienceSerializer(data=item, context={"profile": prof})
                s.is_valid(raise_exception=True)
                created_or_updated.append(s.save())
        return Response(WorkExperienceSerializer(created_or_updated, many=True).data)

    # -------- EDUCATION --------
    @action(detail=False, methods=["post"], url_path="educations")
    def add_education(self, request):
        prof = self._profile(request)
        ser = EducationSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        obj = ser.save(profile=prof)
        return Response(EducationSerializer(obj).data, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=["patch", "delete"], url_path=r"educations/(?P<pk>\d+)")
    def education_detail(self, request, pk=None):
        prof = self._profile(request)
        obj = get_object_or_404(Education, pk=pk, profile=prof)

        if request.method.lower() == "patch":
            ser = EducationSerializer(obj, data=request.data, partial=True)
            ser.is_valid(raise_exception=True)
            obj = ser.save()
            return Response(EducationSerializer(obj).data)

        # DELETE
        obj.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    @action(detail=False, methods=["post"], url_path="educations/bulk")
    def bulk_add_educations(self, request):
        prof = self._profile(request)
        ser = EducationBulkSerializer(data=request.data)
        ser.is_valid(raise_exception=True)

        created = []
        for item in ser.validated_data["items"]:
            obj = Education.objects.create(profile=prof, **item)
            created.append(obj)

        return Response(EducationSerializer(created, many=True).data, status=status.HTTP_201_CREATED)


    # -------- LANGUAGES --------
    @action(detail=False, methods=["post"], url_path="languages")
    def add_language(self, request):
        prof = self._profile(request)
        ser = LanguageEntrySerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        obj = ser.save(profile=prof)
        return Response(LanguageEntrySerializer(obj).data, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=["patch", "delete"], url_path=r"languages/(?P<pk>\d+)")
    def language_detail(self, request, pk=None):
        prof = self._profile(request)
        obj = get_object_or_404(LanguageEntry, pk=pk, profile=prof)

        if request.method.lower() == "patch":
            ser = LanguageEntrySerializer(obj, data=request.data, partial=True)
            ser.is_valid(raise_exception=True)
            obj = ser.save()
            return Response(LanguageEntrySerializer(obj).data)

        # DELETE
        obj.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

# -------- SKILLS --------
    @action(detail=False, methods=["post"], url_path="skills")
    def add_skill(self, request):
        prof = self._profile(request)
        ser = SkillEntrySerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        obj = ser.save(profile=prof)
        return Response(SkillEntrySerializer(obj).data, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=["patch", "delete"], url_path=r"skills/(?P<pk>\d+)")
    def skill_detail(self, request, pk=None):
        prof = self._profile(request)
        obj = get_object_or_404(SkillEntry, pk=pk, profile=prof)

        if request.method.lower() == "patch":
            ser = SkillEntrySerializer(obj, data=request.data, partial=True)
            ser.is_valid(raise_exception=True)
            obj = ser.save()
            return Response(SkillEntrySerializer(obj).data)

        # DELETE
        obj.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
    @action(detail=False, methods=["post"], url_path="skills/bulk")
    def bulk_add_skills(self, request):
        prof = self._profile(request)
        ser = SkillEntryBulkSerializer(data=request.data)
        ser.is_valid(raise_exception=True)

        created = []
        for item in ser.validated_data["items"]:
            obj = SkillEntry.objects.create(profile=prof, **item)
            created.append(obj)

        return Response(SkillEntrySerializer(created, many=True).data, status=status.HTTP_201_CREATED)


@login_required
def my_vacancy_by_category_api(request, category_slug):
    category = get_object_or_404(Category, slug=category_slug)

    if request.user.is_superuser:
        qs = MyVacancy.objects.filter(category=category)
    elif request.user.is_authenticated and request.user.user_type == 'employer':
        qs = MyVacancy.objects.filter(category=category, employer__user=request.user)
    else:
        qs = MyVacancy.objects.none()

    data = [{
        "id": v.id,
        "title": getattr(v, "title", None),
        "location": getattr(v, "location", None),
        "salary": getattr(v, "salary", None),
        "created_at": v.created_at.isoformat() if hasattr(v, "created_at") else None,
    } for v in qs]

    return JsonResponse({
        "category": {"name": category.name, "slug": category.slug},
        "count": len(data),
        "results": data,
    })

@login_required
def dashboard_view(request):
    user = request.user
    context = {
        'user_type': user.user_type,
        'user': user,
    }

    # შეგიძლია სურვილისამებრ დაამატო სხვადსხვა ტიპის ინფო
    if user.user_type == 'admin':
        return render(request, 'admin_dashboard.html', context)
    elif user.user_type == 'employer':
        return render(request, 'employer_dashboard.html', context)
    elif user.user_type == 'job_seeker':
        return render(request, 'dashboard.html', context)
    else:
        return render(request, 'dashboard.html', {'message': 'მომხმარებლის ტიპი უცნობია.'})

# API ROOT
@api_view(['GET'])
def api_root(request):
    return Response({
        "login (HTML form)": "/api/login/",
        "login (API/JWT)": "/api/login/  [POST JSON: {email, password}]",
        "token obtain (username)": "/api/token/",
        "token obtain (email)": "/api/token/email/",
        "token refresh": "/api/token/refresh/",
        "register": "/api/register/",
        "verify-email": "/api/verify-email/?token=...",
        "profile": "/api/profile/",
        "vacancies": "/api/vacancies/",
        "applications": "/api/applications/",
        "categories": "/api/categories/",
        "languages": "/api/languages/",
        "job_seekers": "/api/job_seekers/",
        "swagger": "/api/swagger/",
        "redoc": "/api/redoc/",
    })
# AUTH / LOGIN
# ===========================
class EmailTokenObtainPairView(TokenObtainPairView):
    serializer_class = EmailTokenObtainPairSerializer



class CookieTokenRefreshView(TokenRefreshView):
    """
    Refresh token იღებს HttpOnly Cookie-დან (refresh_token).
    """
    def post(self, request, *args, **kwargs):
        refresh_token = request.COOKIES.get("refresh_token")
        if not refresh_token:
            return Response({"detail": "No refresh token cookie"}, status=400)

        try:
            refresh = RefreshToken(refresh_token)
            data = {
                "access": str(refresh.access_token),
            }
            return Response(data)
        except InvalidToken:
            return Response({"detail": "Invalid refresh token"}, status=401)


@csrf_exempt
@api_view(["POST"])
@permission_classes([AllowAny])
def api_login(request):
    """
    Custom login:
    - Authenticate user by email/password
    - Set both access_token and refresh_token in HttpOnly cookies
    - Return user info in JSON body
    """
    email = request.data.get('email')
    password = request.data.get('password')
    user = authenticate(request, username=email, password=password)

    if not user:
        return Response({"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

    if not user.is_verified:
        return Response({"detail": "გთხოვთ, ჯერ დაადასტურეთ თქვენი ელფოსტა."}, status=status.HTTP_403_FORBIDDEN)

    # Generate tokens
    refresh = RefreshToken.for_user(user)
    access = str(refresh.access_token)

    # Response JSON body – only user info (no tokens here)
    response = Response({
        "user": get_user_profile_info(user)
    })

    # Access token cookie
    response.set_cookie(
        key="access_token",
        value=access,
        httponly=True,
        secure=False,  # True როცა HTTPS გაქვს
        samesite="None",
        max_age=5 * 60  # 5 minutes (access lifetime)
    )

    # Refresh token cookie
    response.set_cookie(
        key="refresh_token",
        value=str(refresh),
        httponly=True,
        secure=False,  # True როცა HTTPS გაქვს
        samesite="None",
        max_age=7 * 24 * 60 * 60  # 7 days
    )

    return response

def custom_login(request):
    """
    Browser session login HTML ფორმით (CSRF აუცილებელია).
    Template: templates/login.html
    """
    if request.method == "POST":
        username_or_email = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(request, username=username_or_email, password=password)
        if user is not None:
            login(request, user)
            return redirect("api-root")
        else:
            return render(request, "login.html", {"error": "არასწორი მონაცემები"})
    return render(request, "login.html")
# CATEGORIES
# ===========================
class CategoryCreateView(generics.CreateAPIView):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    permission_classes = [IsAdmin]

class CategoryListView(generics.ListAPIView):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    permission_classes = [permissions.AllowAny]
# ===========================
# USERS / PROFILES
# ===========================
class RegisterUserView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.AllowAny]

    def perform_create(self, serializer):
        user = serializer.save()

        # ❗️ ახალ რეგისტრირებულს ავტომატურად ვუთიშავთ
        user.is_active = False
        user.is_verified = False
        user.save(update_fields=["is_active", "is_verified"])

        # გავუგზავნოთ ვერიფიკაციის მეილი
        send_verification_email(user)

class UserProfileView(generics.RetrieveUpdateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user

class JobSeekerProfileView(generics.RetrieveUpdateAPIView):
    queryset = JobSeekerProfile.objects.all()
    serializer_class = JobSeekerProfileSerializer
    permission_classes = [IsJobSeeker]

    def get_object(self):
        return get_object_or_404(JobSeekerProfile, user=self.request.user)

class JobSeekerListView(generics.ListAPIView):
    queryset = User.objects.filter(user_type='job_seeker')
    serializer_class = UserSerializer
    permission_classes = [IsEmployer]

class LanguageListView(generics.ListAPIView):
    queryset = Language.objects.all()
    serializer_class = LanguageSerializer
    permission_classes = [permissions.AllowAny]
# ===========================
# EMAIL VERIFICATION
# ===========================
@api_view(['GET'])
def verify_email(request):
    token = request.GET.get('token')
    if not token:
        return Response({"detail": "Token missing"}, status=status.HTTP_400_BAD_REQUEST)
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get('user_id')
        user = User.objects.get(pk=user_id)
    except (jwt.ExpiredSignatureError, jwt.DecodeError, User.DoesNotExist):
        return Response({"detail": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)

    user.is_verified = True
    user.is_active = True
    user.save()

    try:
        send_mail(
            subject="Your account is verified",
            message=f"Hi {user.username}, your account is now verified.Please Weit for admin approval.",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=True,
        )
    except Exception:
        pass

    return Response({"detail": "Email verified successfully"}, status=status.HTTP_200_OK)
# ===========================
# VACANCIES
# ===========================
class VacancyListView(generics.ListAPIView):
    serializer_class = VacancySerializer
    permission_classes = [permissions.AllowAny]

    def get_queryset(self):
        queryset = Vacancy.objects.filter(is_published=True).order_by('-published_date')
        category_id = self.request.query_params.get('category_id')
        location = self.request.query_params.get('location')
        q = self.request.query_params.get('q')

        if category_id:
            queryset = queryset.filter(category__id=category_id)
        if location:
            queryset = queryset.filter(location__icontains=location)
        if q:
            queryset = queryset.filter(title__icontains=q)

        return queryset
    

class VacancyDetailView(generics.RetrieveAPIView):
    queryset = Vacancy.objects.all()
    serializer_class = VacancySerializer
    permission_classes = [permissions.AllowAny]

class VacancyCreateView(generics.CreateAPIView):
    queryset = Vacancy.objects.all()
    serializer_class = VacancyCreateSerializer
    permission_classes = [IsEmployer]

    def perform_create(self, serializer):
     employer_profile = get_object_or_404(EmployerProfile, user=self.request.user)

     # Pending employers cannot post
     if not employer_profile.is_approved_by_admin:
         raise PermissionDenied("თქვენი პროფილი ელოდება ადმინის დადასტურებას.")

     # 📌 აქ ვამოწმებთ პაკეტს
     package = PurchasedService.objects.filter(
         user=self.request.user,
         is_active=True,
         expiry_date__gte=timezone.now()
     ).order_by("-expiry_date").first()

     if not package:
         raise PermissionDenied("აქტიური პაკეტი არ გაქვთ. ვაკანსიის განთავსება შეუძლებელია.")

     # Premium vacancy?
     if serializer.validated_data.get("is_premium", False):
         if package.remaining_premium <= 0:
             raise PermissionDenied("თქვენ აღარ გაქვთ პრემიუმ ვაკანსიების ლიმიტი.")
         package.remaining_premium -= 1
     else:
         if package.remaining_standard <= 0:
             raise PermissionDenied("თქვენ აღარ გაქვთ სტანდარტული ვაკანსიების ლიმიტი.")
         package.remaining_standard -= 1

     package.save()

     # Save vacancy as unpublished (Pending moderation)
     vacancy = serializer.save(employer=employer_profile)

     # Notify admin
     admin_emails = []
     if getattr(settings, 'ADMIN_EMAIL', None):
         admin_emails = [e.strip() for e in settings.ADMIN_EMAIL.split(',') if e.strip()]

     if admin_emails:
         subject = "New vacancy created (pending moderation)"
         message = f"Employer: {employer_profile.company_name}\nVacancy: {vacancy.title}\nLocation: {vacancy.location}"
         try:
             send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, admin_emails, fail_silently=True)
         except Exception:
             pass
            
     # Notify employer
     try:
         send_mail(
             subject="Your vacancy is pending moderation",
             message=f"Your vacancy '{vacancy.title}' is submitted and awaiting admin approval.",
             from_email=settings.DEFAULT_FROM_EMAIL,
             recipient_list=[employer_profile.user.email],
             fail_silently=True,
         )
     except Exception:
         pass
        
     return vacancy

class MyVacancyListView(generics.ListAPIView):
    serializer_class = VacancySerializer
    permission_classes = [IsEmployer]

    def get_queryset(self):
        employer_profile = get_object_or_404(EmployerProfile, user=self.request.user)
        return Vacancy.objects.filter(employer=employer_profile).order_by('-published_date')

class VacancyUpdateDeleteView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Vacancy.objects.all()
    serializer_class = VacancySerializer
    permission_classes = [CanEditVacancy]

    def perform_update(self, serializer):
        instance = self.get_object()
        critical_fields = {'title', 'description', 'requirements', 'min_salary', 'location', 'vacancy_type'}

        updated_data = serializer.validated_data
        critical_changed = False
        changed_fields_list = []
        for field in critical_fields:
            if field in updated_data:
                old_value = getattr(instance, field)
                new_value = updated_data.get(field)
                if old_value != new_value:
                    critical_changed = True
                    changed_fields_list.append(field)

        updated_instance = serializer.save()
        if critical_changed:
            updated_instance.is_published = False
            updated_instance.save()
            admin_emails = []
            if getattr(settings, 'ADMIN_EMAIL', None):
                admin_emails = [e.strip() for e in settings.ADMIN_EMAIL.split(',') if e.strip()]
            if admin_emails:
                subject = "Vacancy requires re-moderation"
                message = (
                    f"Vacancy '{updated_instance.title}' edited by employer "
                    f"'{updated_instance.employer.company_name}'. Changed fields: {', '.join(changed_fields_list)}. "
                    "The vacancy has been set to unpublished (pending)."
                )
                try:
                    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, admin_emails, fail_silently=True)
                except Exception:
                    pass

    def perform_destroy(self, instance):
        instance.is_published = False
        instance.save()
# ===========================
# APPLICATIONS
# ===========================
class ApplicationCreateView(generics.CreateAPIView):
    queryset = Application.objects.all()
    serializer_class = ApplicationSerializer
    permission_classes = [IsJobSeeker]

    def perform_create(self, serializer):
        serializer.save(job_seeker=self.request.user)

class MyApplicationsListView(generics.ListAPIView):
    serializer_class = ApplicationSerializer
    permission_classes = [IsJobSeeker]

    def get_queryset(self):
        return Application.objects.filter(job_seeker=self.request.user).order_by('-applied_at')

class ApplicationUpdateStatusView(generics.UpdateAPIView):
    queryset = Application.objects.all()
    serializer_class = ApplicationSerializer
    permission_classes = [CanUpdateApplicationStatus]

class ApplicationViewSet(viewsets.ModelViewSet):
    queryset = Application.objects.all()
    serializer_class = ApplicationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user

        # --- Admin: ხედავს ყველაფერს ---
        if user.is_superuser or getattr(user, "user_type", "") == "admin":
            return Application.objects.all()

        # --- Job Seeker: მხოლოდ თავისი აპლიკაციები ---
        if getattr(user, "user_type", "") == "job_seeker":
            return Application.objects.filter(job_seeker=user)

        # --- Employer: მხოლოდ თავისი ვაკანსიების აპლიკაციები ---
        if getattr(user, "user_type", "") == "employer":
            return Application.objects.filter(vacancy__employer__user=user)

        return Application.objects.none()

    def perform_create(self, serializer):
        profile = getattr(self.request.user, "jobseekerprofile", None)
        cv_link = None
        if profile and profile.cv:   # თუ პროფილზე ატვირთული აქვს CV
            cv_link = profile.cv.url

        serializer.save(
            job_seeker=self.request.user,
            cv=cv_link   # ← აქ ინახება CV-ის ლინკი პროფილიდან
        )
# ===========================

class GenerateInvoiceView(generics.RetrieveAPIView):
    queryset = Invoice.objects.all()
    serializer_class = InvoiceSerializer

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        context = {'invoice': instance}
        html_string = render_to_string('invoice_template.html', context)
        return HttpResponse(html_string, content_type='text/html')

class AdminProfileViewSet(viewsets.ModelViewSet):
    queryset = AdminProfile.objects.all()
    serializer_class = AdminProfileSerializer
    permission_classes = [IsAdmin]

class EmployerProfileViewSet(viewsets.ModelViewSet):
    queryset = EmployerProfile.objects.all()
    serializer_class = EmployerProfileSerializer
    permission_classes = [IsAdmin | IsEmployer | IsJobSeeker]  # ✅ ყველანაირი წვდომისთვის

    def get_queryset(self):
        user = self.request.user
        qs = super().get_queryset().order_by('-user_id')

        if user.is_superuser or getattr(user, "user_type", "") == "admin":
            return qs  # ✅ Admin sees all

        if getattr(user, "user_type", "") == "employer":
            return qs #.filter(user=user)  # ✅ Employer sees own

        if getattr(user, "user_type", "") == "job_seeker":
            return qs  # ✅ OPTIONAL: if job_seeker should see all (or filter as needed)

        return EmployerProfile.objects.none()  # fallback



@api_view(["GET", "PATCH"])
@permission_classes([IsAuthenticated])
def my_employer_profile(request):
    user = request.user
    if getattr(user, "user_type", "") != "employer":
        return Response({"detail": "მხოლოდ დამსაქმებელს შეუძლია."}, status=403)

    try:
        profile = user.employerprofile
    except EmployerProfile.DoesNotExist:
        return Response({"detail": "პროფილი ვერ მოიძებნა"}, status=404)

    if request.method == "GET":
        ser = EmployerProfileSerializer(profile)
        return Response(ser.data)

    if request.method == "PATCH":
        ser = EmployerProfileSerializer(profile, data=request.data, partial=True)
        ser.is_valid(raise_exception=True)
        ser.save()
        return Response(ser.data)


class JobSeekerProfileViewSet(viewsets.ModelViewSet):
    queryset = JobSeekerProfile.objects.all()
    permission_classes = [IsAdmin | IsEmployer | IsJobSeeker]

    filter_backends = [DjangoFilterBackend]
    filterset_class = JobSeekerProfileFilter
    search_fields = ["user__full_name", "user__email"]

    def get_queryset(self):
        user = self.request.user
        qs = super().get_queryset().order_by('-user_id')

        # ✅ Admin ხედავს ყველას
        if user.is_superuser or getattr(user, "user_type", "") == "admin":
            return qs

        # ✅ Job Seeker ხედავს მხოლოდ საკუთარ პროფილს
        if getattr(user, "user_type", "") == "job_seeker":
            return qs #.filter(user=user)

        # ✅ Employer ხედავს მხოლოდ იმ მაძიებლებს, ვინც მის ვაკანსიებზე მოითხოვა
        if getattr(user, "user_type", "") == "employer":
            applicant_user_ids = Application.objects.filter(
                vacancy__employer__user=user
            ).values_list("job_seeker", flat=True).distinct()
            return qs #.filter(user_id__in=applicant_user_ids)
        

        return JobSeekerProfile.objects.none()
    
    @action(detail=False, methods=["get"], url_path="my-applicants")
    def my_applicants(self, request):
        user = request.user
        if getattr(user, "user_type", "") != "employer":
            return Response({"detail": "მხოლოდ დამსაქმებელს შეუძლია."}, status=403)

        applicant_user_ids = Application.objects.filter(
            vacancy__employer__user=user
        ).values_list("job_seeker_id", flat=True).distinct()

        qs = JobSeekerProfile.objects.filter(user_id__in=applicant_user_ids)
        serializer = JobSeekerProfilePublicSerializer(
            qs, many=True, context={"request": request}
        )
        return Response(serializer.data)

    def get_serializer_class(self):
        user = self.request.user
        if user.is_superuser:
            return JobSeekerProfilePrivateSerializer
        if getattr(user, "user_type", "") == "job_seeker":
            return JobSeekerProfilePrivateSerializer
        # დანარჩენებს (დამსაქმებელიც) — Public ველები
        return JobSeekerProfilePublicSerializer

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAdmin]

class ServiceViewSet(viewsets.ModelViewSet):
    queryset = Service.objects.all()
    serializer_class = ServiceSerializer
    permission_classes = [IsAdmin]

class PurchasedServiceViewSet(viewsets.ModelViewSet):
    queryset = PurchasedService.objects.all()
    serializer_class = PurchasedServiceSerializer
    permission_classes = [IsAdmin | IsEmployer]

class InvoiceViewSet(viewsets.ModelViewSet):
    queryset = Invoice.objects.all()
    serializer_class = InvoiceSerializer
    permission_classes = [IsAdmin | IsEmployer]

class LanguageViewSet(viewsets.ModelViewSet):
    queryset = Language.objects.all()
    serializer_class = LanguageSerializer
    permission_classes = [IsAdmin]

class CategoryViewSet(viewsets.ModelViewSet):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    # GET ყველას, POST/PUT/DELETE — მხოლოდ Admin
    permission_classes = [ReadOnlyOrRole | IsAdmin]

class VacancyViewSet(viewsets.ModelViewSet):
    queryset = Vacancy.objects.all()
    serializer_class = VacancySerializer
    permission_classes = [ReadOnlyOrRole | IsEmployer | IsAdmin]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_class = VacancyFilter
    search_fields = ["title", "description", "employer__company_name"]
    ordering_fields = ["published_date", "min_salary", "title"]
    ordering = ["-published_date"]

    def get_queryset(self):
        qs = super().get_queryset()

        if self.request.method in ("GET", "HEAD", "OPTIONS"):
            now = timezone.now()
            qs = qs.filter(
                is_approved=True,
                is_published=True
            ).filter(
                Q(expiry_date__isnull=True) | Q(expiry_date__gte=now)
            )
            cat = self.request.query_params.get("category")
            if cat:
                qs = qs.filter(category__slug=cat)

            q = self.request.query_params.get("q")
            if q:
                qs = qs.filter(title__icontains=q)
        
        # თუ მომხმარებელი არის დამსაქმებელი, მას უნდა ეჩვენოს მისი საკუთარი ვაკანსიები, მიუხედავად სტატუსისა.
        if self.request.user.is_authenticated and getattr(self.request.user, "user_type", "") == "employer":
            qs = Vacancy.objects.filter(employer__user=self.request.user)

        # თუ მომხმარებელი არის სუპერადმინი, მას უნდა ეჩვენოს ყველა ვაკანსია.
        if self.request.user.is_superuser:
            qs = Vacancy.objects.all()

        return qs
    def perform_create(self, serializer):
        user = self.request.user
        employer_profile = get_object_or_404(EmployerProfile, user=user)

        # მოძებნე აქტიური პაკეტი
        package = PurchasedService.objects.filter(
            user=user,
            is_active=True,
            expiry_date__gte=timezone.now()
        ).order_by("-expiry_date").first()

        if not package:
            raise PermissionDenied("You need an active package to post vacancies.")

        # Premium vacancy
        if serializer.validated_data.get("is_premium", False):
            if package.remaining_premium <= 0:
                raise PermissionDenied("You don't have premium vacancies left in your package.")
            package.remaining_premium -= 1
        else:
            if package.remaining_standard <= 0:
                raise PermissionDenied("You don't have standard vacancies left in your package.")
            package.remaining_standard -= 1

        package.save()

        vacancy = serializer.save(
            employer=employer_profile,
            expiry_date=timezone.now() + timezone.timedelta(days=package.service.duration_days)
        )

        # დამსაქმებელი ვერ ამტკიცებს საკუთარ ვაკანსიას
        if getattr(user, "user_type", "") == "employer" and not user.has_perm("core.can_approve_vacancies"):
            vacancy.is_approved = False
        vacancy.save()

    def perform_update(self, serializer):
        user = self.request.user
        validated = serializer.validated_data

        # Employer-ს არ შეუძლია is_approved-ის შეცვლა (თუ უფლება არა აქვს)
        if getattr(user, "user_type", "") == "employer":
            if not user.has_perm("core.can_approve_vacancies"):
                validated.pop("is_approved", None)

        vacancy = serializer.save()

        # თუ Admin-მა ან დამსაქმებელმა ახალი პაკეტი მიუთითა → განვაახლოთ expiry_date
        package = PurchasedService.objects.filter(
            user=vacancy.employer.user,
            is_active=True,
            expiry_date__gte=timezone.now()
        ).order_by("-expiry_date").first()

        if package:
            vacancy.expiry_date = timezone.now() + timezone.timedelta(days=package.service.duration_days)
            vacancy.save()

    @action(detail=False, methods=["get"], url_path="expired", permission_classes=[IsEmployer|IsAdmin])
    def expired(self, request):
        now = timezone.now()
        user = request.user

        if user.is_superuser:
            qs = self.queryset.filter(expiry_date__lt=now, is_published=True).order_by("-expiry_date")
        elif getattr(user, "user_type", "") == "employer":
            qs = self.queryset.filter(expiry_date__lt=now, is_published=True, employer__user=user).order_by("-expiry_date")
        else:
            return Response({"detail": "მხოლოდ დამსაქმებელს ან ადმინს შეუძლია."}, status=403)

        serializer = self.get_serializer(qs, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=["get"], url_path="drafts", permission_classes=[IsEmployer|IsAdmin])
    def drafts(self, request):
        user = request.user

        if user.is_superuser:
            qs = self.queryset.filter(is_published=False).order_by("-published_date")
        elif getattr(user, "user_type", "") == "employer":
            qs = self.queryset.filter(is_published=False, employer__user=user).order_by("-published_date")
        else:
            return Response({"detail": "მხოლოდ დამსაქმებელს ან ადმინს შეუძლია."}, status=403)

        serializer = self.get_serializer(qs, many=True)
        return Response(serializer.data)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def preferred_vacancies(request):
    """
    აბრუნებს მხოლოდ იმ ვაკანსიებს, რომლებიც ერგება JobSeeker-ის სასურველ კატეგორიებს.
    """
    user = request.user

    try:
        profile = user.jobseekerprofile
    except:
        return Response({"detail": "Job seeker profile not found"}, status=404)

    categories = profile.preferred_categories.all()
    if not categories.exists():
        return Response({"detail": "No preferred categories selected"}, status=200)

    vacancies = Vacancy.objects.filter(
        is_approved=True,
        is_published=True,
        category__in=categories
    ).order_by("-published_date")

    serializer = VacancySerializer(vacancies, many=True)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([AllowAny])  # ან საჭიროების მიხედვით შეცვალე
def premium_vacancies(request):

    """
    აბრუნებს მხოლოდ პრემიუმ ვაკანსიებს (დამტკიცებული და გამოქვეყნებული).
    """
    vacancies = Vacancy.objects.filter(
        is_premium=True,
        is_approved=True,
        is_published=True
    ).order_by("-published_date")

    serializer = VacancySerializer(vacancies, many=True)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def my_premium_vacancies(request):
    user = request.user

    # ამოწმებს რომ მხოლოდ დამსაქმებელმა გამოიყენოს
    if not hasattr(user, 'employerprofile'):
        return Response({"detail": "მხოლოდ დამსაქმებელს შეუძლია პრემიუმ ვაკანსიების ნახვა."}, status=403)

    # ფილტრავს ამ employer-ის პრემიუმ ვაკანსიებს
    vacancies = Vacancy.objects.filter(
        employer=user.employerprofile,
        is_published=True,
        is_approved=True,
        is_premium=True
    ).order_by("-published_date")

    serializer = VacancySerializer(vacancies, many=True)
    return Response(serializer.data)

def perform_create(self, serializer):
    user = self.request.user
    employer_profile = get_object_or_404(EmployerProfile, user=user)

    # მოძებნე აქტიური პაკეტი
    package = PurchasedService.objects.filter(
        user=user,
        is_active=True,
        expiry_date__gte=timezone.now()
    ).order_by("-expiry_date").first()

    if not package:
        raise PermissionDenied("You need an active package to post vacancies.")

    # Premium vacancy
    if serializer.validated_data.get("is_premium", False):
        if package.remaining_premium <= 0:
            raise PermissionDenied("You don't have premium vacancies left in your package.")
        package.remaining_premium -= 1
    else:
        if package.remaining_standard <= 0:
            raise PermissionDenied("You don't have standard vacancies left in your package.")
        package.remaining_standard -= 1

    package.save()

    vacancy = serializer.save(employer=employer_profile)

    # დამსაქმებელი ვერ ამტკიცებს საკუთარ ვაკანსიას
    if getattr(user, "user_type", "") == "employer" and not user.has_perm("core.can_approve_vacancies"):
        vacancy.is_approved = False
    vacancy.save()

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def my_package_status(request):

    user = request.user
    if not hasattr(user, "employerprofile"):
        return Response({"detail": "მხოლოდ დამსაქმებლებს აქვთ პაკეტის ინფორმაცია."}, status=403)

    package = PurchasedService.objects.filter(
        user=user,
        is_active=True,
    ).filter(
        models.Q(expiry_date__isnull=True) | models.Q(expiry_date__gte=timezone.now())
        ).first()
    if not package:
        return Response({"detail": "აქტიური პაკეტი არ გაქვთ."}, status=404)

    return Response({
        "service": package.service.name,
        "expiry_date": package.expiry_date,
        "remaining_premium": package.remaining_premium,
        "remaining_standard": package.remaining_standard
    })

@api_view(["GET"])
@permission_classes([AllowAny])  
def service_list(request):
    """
    აბრუნებს ყველა ხელმისაწვდომ სერვისს (პაკეტს)
    """
    services = Service.objects.all()
    serializer = ServiceSerializer(services, many=True)
    return Response(serializer.data)

@api_view(["GET"])
@permission_classes([AllowAny])
def service_detail(request, pk):

    """
    აბრუნებს კონკრეტული სერვისის დეტალებს
    """
    try:
        service = Service.objects.get(pk=pk)
    except Service.DoesNotExist:
        return Response({"detail": "Service not found"}, status=404)

    serializer = ServiceSerializer(service)
    return Response(serializer.data)

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def create_invoice_for_service(request, service_id):
    """
    ქმნის ინვოისს კონკრეტული სერვისისთვის (placeholder სტატუსით)
    """
    user = request.user

    # მოიძებნოს სერვისი
    service = get_object_or_404(Service, pk=service_id)

    # თუ უკვე არსებობს მსგავსი ინვოისი და ჯერ არ არის გადახდილი
    existing = Invoice.objects.filter(
        user=user,
        service=service,
        status="unpaid"
    ).first()

    if existing:
        return Response(
            {"detail": "გადაუხდელი ინვოისი უკვე არსებობს ამ სერვისზე.", "invoice_id": existing.id},
            status=status.HTTP_400_BAD_REQUEST
        )

    invoice = Invoice.objects.create(
        user=user,
        service=service,
        amount=service.price,
        status="unpaid"  # Placeholder
    )

    return Response({
        "invoice_id": invoice.id,
        "amount": invoice.amount,
        "status": invoice.status,
        "service": invoice.service.name,
        "user_id": invoice.user.id,
        "user_email": invoice.user.email,
        })

class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]


    def post(self, request):
        user = request.user
        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')
        confirm_password = request.data.get('confirm_password')

        if not old_password or not new_password or not confirm_password:
            return Response({'error': 'ყველა ველის შევსება აუცილებელია.'}, status=400)

        if new_password != confirm_password:
            return Response({'error': 'ახალი პაროლი და გამეორებული პაროლი არ ემთხვევა.'}, status=400)

        if not user.check_password(old_password):
            return Response({'error': 'ძველი პაროლი არასწორია.'}, status=400)

        try:
            validate_password(new_password, user)
        except ValidationError as e:
            return Response({'error': e.messages}, status=400)

        user.set_password(new_password)
        user.save()
        return Response({'success': 'პაროლი წარმატებით შეიცვალა.'})
    


@api_view(["POST"])
@permission_classes([IsAuthenticated, IsEmployer])
def create_test_view(request, vacancy_id):
    """
    ქმნის Google Form-ს კონკრეტული ვაკანსიისთვის.
    თუ ვაკანსიაზე ტესტი უკვე არსებობს:
      - replace=false  → დააბრუნებს 409 ("უკვე არსებობს")
      - replace=true   → იგივე Test ჩანაწერზე გადაიწერება form_id (და სურვილისამებრ წაიშლება ძველი შედეგები)
    """
    try:
        vacancy = Vacancy.objects.get(id=vacancy_id, employer__user=request.user)
    except Vacancy.DoesNotExist:
        return Response({"error": "Vacancy not found or not yours"}, status=status.HTTP_404_NOT_FOUND)

    data = request.data if isinstance(request.data, dict) else {}

    title          = data.get("title") or f"Test for {vacancy.title}"
    description    = data.get("description")
    settings       = data.get("settings") or {}
    items          = data.get("items") or []
    replace        = bool(data.get("replace", False))          # <— მთავარი ფლაგი
    drop_old_res   = bool(data.get("drop_old_results", False)) # სურვილისამებრ ძველი შედეგების წაშლა

    # შექმენი ახალი Google Form (items/settings თუ გაქვს — batchUpdate-ით წაიყვანს)
    if items or settings:
        meta = create_form_with_items(
            user=request.user,
            title=title,
            description=description,
            collect_email=bool(settings.get("collect_email", True)),
            is_quiz=bool(settings.get("is_quiz", True)),
            items=items,
        )
    else:
        meta = create_google_form(request.user, title=title, description=description)

    if not meta:
        return Response({"error": "Google Form creation failed"}, status=status.HTTP_400_BAD_REQUEST)

    # ვცდილობთ ვიპოვოთ არსებული Test ამ ვაკანსიაზე
    try:
        test = Test.objects.get(vacancy=vacancy, employer=request.user)

        if not replace:
            return Response(
                {"error": "Test already exists for this vacancy. Pass replace=true to overwrite."},
                status=status.HTTP_409_CONFLICT
            )

        old_form_id = test.form_id
        test.form_id = meta["formId"]
        test.title   = meta.get("title") or title
        test.save(update_fields=["form_id", "title"])

        if drop_old_res:
            TestResult.objects.filter(test=test).delete()

        return Response(
            {
                "test": TestSerializer(test).data,
                "form_url": meta.get("responderUri"),
                "replaced_old_form_id": old_form_id,
                "note": "Existing Test updated to point to a new Google Form."
            },
            status=status.HTTP_201_CREATED,
        )

    except Test.DoesNotExist:
        # არ არსებობს — გავქმნათ პირველად
        test = Test.objects.create(
            vacancy=vacancy,
            employer=request.user,
            form_id=meta["formId"],
            title=meta.get("title") or title,
        )
        return Response(
            {"test": TestSerializer(test).data, "form_url": meta.get("responderUri")},
            status=status.HTTP_201_CREATED,
        )


@api_view(["GET"])
@permission_classes([IsAuthenticated, IsEmployer])
def get_test_results_view(request, vacancy_id):

    try:
        test = Test.objects.get(vacancy__id=vacancy_id, employer=request.user)
    except Test.DoesNotExist:
        return Response({"error": "Test not found"}, status=status.HTTP_404_NOT_FOUND)

    responses = get_form_responses(request.user, test.form_id) or []
    results = []

    for resp in responses:
        response_id = resp.get("responseId")
        if not response_id:
            continue

        # submitted_at awareness
        submitted_raw = resp.get("lastSubmittedTime")
        submitted_at = parse_datetime(submitted_raw) if submitted_raw else None
        if submitted_at and timezone.is_naive(submitted_at):
            submitted_at = timezone.make_aware(submitted_at, timezone.utc)

        # normalize email
        respondent_email = (resp.get("respondentEmail") or "").strip().lower() or None

        total_score = resp.get("totalScore")
        answers = resp.get("answers", {})

        # upsert TestResult
        result, created = TestResult.objects.get_or_create(
            test=test,
            response_id=response_id,
            defaults={
                "application": None,
                "respondent_email": respondent_email,   
                "answers": answers,
                "total_score": total_score,
                "submitted_at": submitted_at or timezone.now(),
            },
        )

        changed = False
   
        if not created:
            if respondent_email and result.respondent_email != respondent_email:
                result.respondent_email = respondent_email
                changed = True
            if total_score is not None and result.total_score != total_score:
                result.total_score = total_score
                changed = True
            if answers and result.answers != answers:
                result.answers = answers
                changed = True
            if submitted_at and result.submitted_at != submitted_at:
                result.submitted_at = submitted_at
                changed = True


        if respondent_email and result.application_id is None:
            app = Application.objects.filter(
                vacancy_id=vacancy_id,
                job_seeker__email__iexact=respondent_email
            ).first()
            if app:
                result.application = app
                changed = True

        if changed:
            result.save()

        results.append(result)


    return Response(TestResultSerializer(results, many=True).data, status=status.HTTP_200_OK)



class CustomLoginView(TokenObtainPairView):
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)

        # Access და Refresh თოკენები
        token_data = response.data
        access_token = token_data.get("access")
        refresh_token = token_data.get("refresh")

        # წაშლა data-დან, თუ არ გინდა რომ body-შიც იყოს
        response.data.pop("access", None)
        response.data.pop("refresh", None)

        # Cookie-ში ჩასმა
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=True,  # თუ HTTPS იყენებ
            samesite="Lax",  # ან "None" თუ cross-site მოთხოვნებია საჭირო
            max_age=3600  # 1 საათი მაგალითად
        )
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            secure=True,
            samesite="Lax",
            max_age=7 * 24 * 60 * 60  # Refresh token-ის ვადა (7 დღე)
        )

        return response
    
class CookieTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        # Body-ის ნაცვლად ქუქიდან წამოიღე refresh token
        request.data["refresh"] = request.COOKIES.get("refresh_token")
        response = super().post(request, *args, **kwargs)

        new_access_token = response.data.get("access")
        response.data.pop("access", None)

        response.set_cookie(
            key="access_token",
            value=new_access_token,
            httponly=True,
            secure=True,
            samesite="Lax",
            max_age=3600
        )

        return response
    
class LogoutView(APIView):
    def post(self, request):
        response = Response()
        response.delete_cookie('access_token')
        response.delete_cookie('refresh_token')
        return response