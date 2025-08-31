from django.urls import path
from .views import (
    api_root,
    api_login,          # API login (JWT), CSRF exempt
    custom_login,       # HTML form login
    RegisterUserView,
    VacancyListView,
    VacancyCreateView,
    ApplicationCreateView,
    VacancyDetailView,
    GenerateInvoiceView,
    MyVacancyListView,
    VacancyUpdateDeleteView,
    ApplicationUpdateStatusView,
    CategoryListView,
    CategoryCreateView,
    JobSeekerListView,
    MyApplicationsListView,
    UserProfileView,
    JobSeekerProfileView,
    LanguageListView,
    verify_email,
)

urlpatterns = [
    # Root + logins
    path('', api_root, name="api-root"),
    path('login/', custom_login, name='login'),      # HTML form
    path('api/login/', api_login, name='api_login'), # API/JWT login

    # Auth/Users
    path('register/', RegisterUserView.as_view(), name='register'),
    path('verify-email/', verify_email, name='verify-email'),
    path('profile/', UserProfileView.as_view(), name='user-profile'),
    path('profile/job_seeker/', JobSeekerProfileView.as_view(), name='job-seeker-profile'),

    # Vacancies
    path('vacancies/', VacancyListView.as_view(), name='vacancy-list'),
    path('vacancies/my/', MyVacancyListView.as_view(), name='my-vacancies'),
    path('vacancies/<int:pk>/', VacancyDetailView.as_view(), name='vacancy-detail'),
    path('vacancies/create/', VacancyCreateView.as_view(), name='vacancy-create'),
    path('vacancies/<int:pk>/update/', VacancyUpdateDeleteView.as_view(), name='vacancy-update'),
    path('vacancies/<int:pk>/delete/', VacancyUpdateDeleteView.as_view(), name='vacancy-delete'),

    # Applications
    path('applications/create/', ApplicationCreateView.as_view(), name='application-create'),
    path('applications/my/', MyApplicationsListView.as_view(), name='my-applications'),
    path('applications/<int:pk>/update_status/', ApplicationUpdateStatusView.as_view(), name='application-update-status'),

    # Categories / Languages
    path('categories/', CategoryListView.as_view(), name='category-list'),
    path('categories/create/', CategoryCreateView.as_view(), name='category-create'),
    path('languages/', LanguageListView.as_view(), name='language-list'),

    # Other
    path('job_seekers/', JobSeekerListView.as_view(), name='job-seeker-list'),
    path('invoices/<int:pk>/generate/', GenerateInvoiceView.as_view(), name='generate-invoice'),
]
