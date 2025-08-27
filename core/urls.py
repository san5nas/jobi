from django.urls import path
from .views import (
    api_root,
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
    LanguageListView
)

from django.urls import path
from .views import custom_login
urlpatterns = [
    
    path('', api_root, name="api-root"),
    
    path("login/", custom_login, name="login"),

    # მომხმარებლის მართვა
    path('register/', RegisterUserView.as_view(), name='register'),
    path('profile/', UserProfileView.as_view(), name='user-profile'),
    path('profile/job_seeker/', JobSeekerProfileView.as_view(), name='job-seeker-profile'),

    # ვაკანსიის მართვა
    path('vacancies/', VacancyListView.as_view(), name='vacancy-list'),
    path('vacancies/my/', MyVacancyListView.as_view(), name='my-vacancies'),
    path('vacancies/<int:pk>/', VacancyDetailView.as_view(), name='vacancy-detail'),
    path('vacancies/create/', VacancyCreateView.as_view(), name='vacancy-create'),
    path('vacancies/<int:pk>/update/', VacancyUpdateDeleteView.as_view(), name='vacancy-update'),
    path('vacancies/<int:pk>/delete/', VacancyUpdateDeleteView.as_view(), name='vacancy-delete'),

    # განაცხადის მართვა
    path('applications/create/', ApplicationCreateView.as_view(), name='application-create'),
    path('applications/my/', MyApplicationsListView.as_view(), name='my-applications'),
    path('applications/<int:pk>/update_status/', ApplicationUpdateStatusView.as_view(), name='application-update-status'),

    # კატეგორიის და ენების მართვა
    path('categories/', CategoryListView.as_view(), name='category-list'),
    path('categories/create/', CategoryCreateView.as_view(), name='category-create'),
    path('languages/', LanguageListView.as_view(), name='language-list'),

    # მონაცემთა ბაზაზე წვდომა
    path('job_seekers/', JobSeekerListView.as_view(), name='job-seeker-list'),

    # ინვოისის მართვა
    path('invoices/<int:pk>/generate/', GenerateInvoiceView.as_view(), name='generate-invoice'),
]