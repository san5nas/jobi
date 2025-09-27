# core/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from core.views import preferred_vacancies

from .views import (
    api_root, api_login, custom_login,
    RegisterUserView, verify_email,
    UserProfileView, JobSeekerProfileView,
    GenerateInvoiceView, VacancyCreateView, MyVacancyListView,
    MyApplicationsListView, ApplicationCreateView, ApplicationUpdateStatusView,
    VacancyListView,
    UserViewSet, AdminProfileViewSet, EmployerProfileViewSet,
    JobSeekerProfileViewSet, ServiceViewSet, PurchasedServiceViewSet,
    InvoiceViewSet, CategoryViewSet, LanguageViewSet,
    VacancyViewSet, ApplicationViewSet, MyProfileViewSet,
    my_vacancy_by_category_api,google_login_callback_json,
    google_login_url,my_package_status,my_employer_profile,ChangePasswordView,get_test_results_view,create_test_view
)
from . import calendar_views
from .calendar_views import create_interview_meeting_view, interview_status_view
from core import views
from .views import premium_vacancies
from .views import my_premium_vacancies

from rest_framework_simplejwt.views import TokenRefreshView
from core.views import EmailTokenObtainPairView 

from .views import create_invoice_for_service

from .views import service_list, service_detail

from .views import RequestPasswordResetView
from .views import PasswordResetConfirmView

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
router.register(r'me/profile', MyProfileViewSet, basename='me-profile')

urlpatterns = [
    # Static endpoints
    path('', api_root, name="api-root"),
    path('login/', custom_login, name='login'),
    path('api/login/', api_login, name='api_login'),
    path('register/', RegisterUserView.as_view(), name='register'),
    path('verify-email/', verify_email, name='verify-email'),
    path('profile/', UserProfileView.as_view(), name='user-profile'),
    path('profile/job_seeker/', JobSeekerProfileView.as_view(), name='job-seeker-profile'),
    path("me/employer-profile/", my_employer_profile, name="my-employer-profile"),

    path("api/token/", EmailTokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("api/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),

    path('auth/change-password/', ChangePasswordView.as_view(), name='change-password'),
    path("request-password-reset/", RequestPasswordResetView.as_view(), name="request-password-reset"),
    path("reset-password-confirm/", PasswordResetConfirmView.as_view(), name="reset-password-confirm"),

    # Vacancy endpoints
    path('vacancies/my/', MyVacancyListView.as_view(), name='my-vacancies'),
    path('vacancies/create/', VacancyCreateView.as_view(), name='vacancy-create'),
    path('myvacancy/<slug:category_slug>/', my_vacancy_by_category_api, name='myvacancy_by_category_api'),

    # სასურველი ვაკანსიები
    path("vacancies/premium/", views.premium_vacancies, name="premium-vacancies"),
    path("vacancies/my-premium/", my_premium_vacancies, name="my-premium-vacancies"),
    path("vacancies/preferred/", preferred_vacancies, name="preferred-vacancies"),


    # სერვისები
    path("services/", service_list, name="service-list"),
    path("services/<int:pk>/", service_detail, name="service-detail"),
    path("services/<int:service_id>/create-invoice/", create_invoice_for_service, name="create-invoice-for-service"),
    path("my-package/", my_package_status, name="my-package"),

    # Application endpoints
    path('applications/create/', ApplicationCreateView.as_view(), name='application-create'),
    path('applications/my/', MyApplicationsListView.as_view(), name='my-applications'),
    path('applications/<int:pk>/update_status/', ApplicationUpdateStatusView.as_view(), name='application-update-status'),
    path('invoices/<int:pk>/generate/', GenerateInvoiceView.as_view(), name='generate-invoice'),

    # Google Calendar / Meet
    path("create-meeting/", calendar_views.create_meeting_view, name="create-meeting"),
    path('interviews/<int:application_id>/create-meeting/', create_interview_meeting_view, name='create-interview-meeting'),
    path('interviews/<int:application_id>/status/', interview_status_view, name='interview-status'),
    path('google-calendar/init/', calendar_views.google_calendar_init_view, name='google_calendar_init'),
    path('google-calendar/redirect/', calendar_views.google_calendar_redirect_view, name='google_calendar_redirect'),
    path('google-calendar/status/', calendar_views.google_calendar_status_view, name='google_calendar_status'),
    path("auth/google/login-url/", google_login_url, name="google-login-url"),
    path("auth/google/callback-json/", google_login_callback_json, name="google-callback-json"),
    path("google-calendar/events/", calendar_views.google_calendar_events_view, name="google_calendar_events"),
    path("tests/create/<int:vacancy_id>/", views.create_test_view, name="create-test"),
    path("tests/<int:vacancy_id>/results/", views.get_test_results_view, name="test-results"),
    

    
    path('', include(router.urls)),
]