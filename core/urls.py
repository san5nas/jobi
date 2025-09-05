# core/urls.py

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .calendar_views import create_interview_meeting_view

from .views import (
    api_root,
    api_login,
    custom_login,
    RegisterUserView,
    verify_email,
    UserProfileView,
    JobSeekerProfileView,
    GenerateInvoiceView,
    VacancyCreateView,
    MyVacancyListView,
    MyApplicationsListView,
    ApplicationCreateView,
    ApplicationUpdateStatusView,
    VacancyListView,
    # ახალი ViewSets
    UserViewSet,
    AdminProfileViewSet,
    EmployerProfileViewSet,
    JobSeekerProfileViewSet,
    ServiceViewSet,
    PurchasedServiceViewSet,
    InvoiceViewSet,
    CategoryViewSet,
    LanguageViewSet,
    VacancyViewSet,
    ApplicationViewSet,
    
)
from . import views

from . import calendar_views
from .calendar_views import create_meeting_view
from .views import my_vacancy_by_category_api


router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'admin-profiles', AdminProfileViewSet, basename='admin-profile')
router.register(r'employer-profiles', EmployerProfileViewSet, basename='employer-profile')
router.register(r'job-seeker-profiles', JobSeekerProfileViewSet, basename='job-seeker-profile')
router.register(r'services', ServiceViewSet, basename='service')
router.register(r'purchased-services', PurchasedServiceViewSet, basename='purchased-service')
router.register(r'invoices', InvoiceViewSet, basename='invoice')
router.register(r'categories', CategoryViewSet, basename='category')
router.register(r'languages', LanguageViewSet, basename='language')
router.register(r'vacancies', VacancyViewSet, basename='vacancy')
router.register(r'applications', ApplicationViewSet, basename='application')


urlpatterns = [
    # ესენი ჩაიტანება /api/ ქვეშ (ამიტომ მისამართები იქნება /api/...)
    path('', api_root, name="api-root"),
    path('login/', custom_login, name='login'),
    path('api/login/', api_login, name='api_login'),
    path('register/', RegisterUserView.as_view(), name='register'),
    path('verify-email/', verify_email, name='verify-email'),
    path('profile/', UserProfileView.as_view(), name='user-profile'),
    path('profile/job_seeker/', JobSeekerProfileView.as_view(), name='job-seeker-profile'),

    # ✅ JSON endpoint კატეგორიით (ახლა იქნება /api/myvacancy/it/)
    path('myvacancy/<slug:category_slug>/', my_vacancy_by_category_api, name='myvacancy_by_category_api'),

    # სხვა API-ები
    path('vacancies/my/', MyVacancyListView.as_view(), name='my-vacancies'),
    path('vacancies/create/', VacancyCreateView.as_view(), name='vacancy-create'),
    path('applications/create/', ApplicationCreateView.as_view(), name='application-create'),
    path('applications/my/', MyApplicationsListView.as_view(), name='my-applications'),
    path('applications/<int:pk>/update_status/', ApplicationUpdateStatusView.as_view(), name='application-update-status'),
    path('invoices/<int:pk>/generate/', GenerateInvoiceView.as_view(), name='generate-invoice'),
    path('dashboard/', views.dashboard_view, name='dashboard'),

    # Google Meet/Calendar
    path("create-meeting/", calendar_views.create_meeting_view, name="create-meeting"),
    path('interviews/<int:application_id>/create-meeting/', create_interview_meeting_view, name='create-interview-meeting'),
    path('google-calendar/init/', calendar_views.google_calendar_init_view, name='google_calendar_init'),
    path('google-calendar/redirect/', calendar_views.google_calendar_redirect_view, name='google_calendar_redirect'),
    path('google-calendar/status/', calendar_views.google_calendar_status_view, name='google_calendar_status'),

    # Router (ViewSet-ები) — აუცილებლად ბოლოდ დაგვრჩეს
    path('', include(router.urls)),
]
