import django_filters
from .models import Vacancy
from .models import JobSeekerProfile

class VacancyFilter(django_filters.FilterSet):
    salary_min = django_filters.NumberFilter(field_name="min_salary", lookup_expr="gte")
    salary_max = django_filters.NumberFilter(field_name="min_salary", lookup_expr="lte")
    location = django_filters.CharFilter(field_name="location", lookup_expr="icontains")
    category = django_filters.NumberFilter(field_name="category__id")  # ან category__slug თუ სლაგით გინდა
    vacancy_type = django_filters.CharFilter(field_name="vacancy_type", lookup_expr="iexact")  
    category_slug = django_filters.CharFilter(field_name="category__slug", lookup_expr="iexact")
    employer = django_filters.NumberFilter(field_name="employer")
    published_after = django_filters.DateFilter(field_name="published_date", lookup_expr="gte")
    published_before = django_filters.DateFilter(field_name="published_date", lookup_expr="lte")
    published_range = django_filters.DateFromToRangeFilter(field_name="published_date")
    company_name = django_filters.CharFilter(field_name="employer__company_name", lookup_expr="icontains")
    
    class Meta:
        model = Vacancy
        fields = ["location", "category","category_slug", "vacancy_type", "salary_min", "salary_max","employer","published_after", "published_before","published_date","company_name"]




class JobSeekerProfileFilter(django_filters.FilterSet):
    full_name = django_filters.CharFilter(
        field_name="user__full_name",
        lookup_expr="icontains"
    )

    class Meta:
        model = JobSeekerProfile
        fields = ["full_name"]