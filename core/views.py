from django.shortcuts import get_object_or_404, render, redirect
from django.http import HttpResponse
from django.template.loader import render_to_string

from rest_framework import generics, permissions
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework.exceptions import PermissionDenied

from django.contrib.auth import authenticate, login

from .models import (
    User, Vacancy, Application, EmployerProfile, Category, Invoice,
    JobSeekerProfile, Language
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
)
from .permissions import IsEmployer, IsAdmin, IsJobSeeker, CanEditVacancy, CanUpdateApplicationStatus

# --- JWT email login view ---
from rest_framework_simplejwt.views import TokenObtainPairView


@api_view(['GET'])
def api_root(request):
    return Response({
        "login": "/api/login/",
        "register": "/api/register/",
        "profile": "/api/profile/",
        "vacancies": "/api/vacancies/",
        "applications": "/api/applications/",
        "categories": "/api/categories/",
        "languages": "/api/languages/",
        "job_seekers": "/api/job_seekers/",
        "swagger": "/api/swagger/",
        "redoc": "/api/redoc/",
    })


# --- Session-based custom login (ბრაუზერის ფორმისთვის; API-სთვის გამოიყენე JWT) ---
def custom_login(request):
    """
    Login with username or email (session auth).
    API-სთვის გამოიყენე /api/token/ ან /api/token/email/
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


class EmailTokenObtainPairView(TokenObtainPairView):
    serializer_class = EmailTokenObtainPairSerializer


# ---------- Categories ----------
class CategoryCreateView(generics.CreateAPIView):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    permission_classes = [IsAdmin]


class CategoryListView(generics.ListAPIView):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    permission_classes = [permissions.AllowAny]


# ---------- Users / Profiles ----------
class RegisterUserView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.AllowAny]


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


# ---------- Vacancies ----------
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

        # მოთხოვნა: Pending დამსაქმებელს არ ჰქონდეს რესურსების გამოქვეყნება
        if not employer_profile.is_approved_by_admin:
            raise PermissionDenied("თქვენი პროფილი ელოდება ადმინის დადასტურებას.")

        # სურვილისამებრ: ახალი ვაკანსია შეიძლება იყოს Pending (მოდერაცია)
        vacancy = serializer.save(employer=employer_profile, is_published=False)
        # აქ შეგიძლია დაამატო ელფოსტის გაგზავნა admin-სთვის/დამსაქმებლისთვის
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

    def perform_destroy(self, instance):
        instance.is_published = False
        instance.save()


# ---------- Applications ----------
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


# ---------- Invoices ----------
class GenerateInvoiceView(generics.RetrieveAPIView):
    queryset = Invoice.objects.all()
    serializer_class = InvoiceSerializer  # ← ეს აკლდა და WARNING-ს ყრიდა

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        context = {'invoice': instance}
        html_string = render_to_string('invoice_template.html', context)
        return HttpResponse(html_string, content_type='text/html')
