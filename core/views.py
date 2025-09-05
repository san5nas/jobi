from django.shortcuts import get_object_or_404, render, redirect
from django.http import HttpResponse
from django.template.loader import render_to_string
from django.views.decorators.csrf import csrf_exempt

from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework.exceptions import PermissionDenied

from django.contrib.auth import authenticate, login
from django.core.mail import send_mail
from django.conf import settings

from rest_framework import viewsets
import jwt

from .models import (
    User, Vacancy, Application, EmployerProfile, Category, Invoice,
    JobSeekerProfile, Language, AdminProfile, Service, PurchasedService,
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
    
)
from .permissions import IsEmployer, IsAdmin, IsJobSeeker, CanEditVacancy, CanUpdateApplicationStatus
from .utils import send_verification_email

from .permissions import ReadOnlyOrRole
# --- JWT email login view ---
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken


from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from .models import MyVacancy
from django.http import JsonResponse


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


# ===========================
# API ROOT
# ===========================
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


# ===========================
# AUTH / LOGIN
# ===========================
class EmailTokenObtainPairView(TokenObtainPairView):
    serializer_class = EmailTokenObtainPairSerializer


@csrf_exempt           # ← CSRF არაა საჭირო API-დან ავტენტიკაციისას
@api_view(['POST'])
def api_login(request):
    """
    API Login — გამოიყენე Postman-იდან:
    POST /api/login/
    Body (JSON): {"email": "...", "password": "..."}
    Response: {"refresh": "...", "access": "..."}
    """
    email = request.data.get('email')
    password = request.data.get('password')
    user = authenticate(request, username=email, password=password)
    if user:
        refresh = RefreshToken.for_user(user)
        return Response({
            "refresh": str(refresh),
            "access": str(refresh.access_token),
        })
    return Response({"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)


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


# ===========================
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
        # მომხმარებელი იქმნება; email-ის ვერიფიკაციის ბმული იგზავნება
        user = serializer.save()
        try:
            send_verification_email(user)
        except Exception:
            pass


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
            message=f"Hi {user.username}, your account is now verified and active.",
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

        # Save vacancy as unpublished (Pending moderation)
        vacancy = serializer.save(employer=employer_profile, is_published=False)

        # Notify admin about new vacancy (email)
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


# ===========================
# INVOICES
# ===========================
class GenerateInvoiceView(generics.RetrieveAPIView):
    queryset = Invoice.objects.all()
    serializer_class = InvoiceSerializer

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        context = {'invoice': instance}
        html_string = render_to_string('invoice_template.html', context)
        return HttpResponse(html_string, content_type='text/html')
# core/views.py

# ... დატოვეთ თქვენი არსებული იმპორტები და ხედები (views) უცვლელად ...
# ... მაგალითად: VacancyListView, VacancyCreateView, UserProfileView და ა.შ.



class AdminProfileViewSet(viewsets.ModelViewSet):
    queryset = AdminProfile.objects.all()
    serializer_class = AdminProfileSerializer
    permission_classes = [IsAdmin]

class EmployerProfileViewSet(viewsets.ModelViewSet):
    queryset = EmployerProfile.objects.all()
    serializer_class = EmployerProfileSerializer
    permission_classes = [IsAdmin | IsEmployer]

class JobSeekerProfileViewSet(viewsets.ModelViewSet):
    queryset = JobSeekerProfile.objects.all()
    serializer_class = JobSeekerProfileSerializer
    permission_classes = [IsAdmin | IsJobSeeker]

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

class CategoryViewSet(viewsets.ModelViewSet):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    permission_classes = [IsAdmin]

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
    # GET ყველას, წერადი — Admin ან Employer
    permission_classes = [ReadOnlyOrRole | IsEmployer | IsAdmin]
    search_fields = ["title", "location"]
    ordering_fields = ["created_at", "salary", "title"]

    def get_queryset(self):
        qs = super().get_queryset()
        # საჯარო კითხვაზე — მხოლოდ გამოქვეყნებული
        if self.request.method in ("GET", "HEAD", "OPTIONS"):
            qs = qs.filter(is_published=True)

            # ფილტრი query param-ებით
            cat = self.request.query_params.get("category")
            if cat:
                qs = qs.filter(category__slug=cat)

            q = self.request.query_params.get("q")
            if q:
                qs = qs.filter(title__icontains=q)

        return qs

class ApplicationViewSet(viewsets.ModelViewSet):
    queryset = Application.objects.all()
    serializer_class = ApplicationSerializer
    permission_classes = [IsJobSeeker | IsAdmin]