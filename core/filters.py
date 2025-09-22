import django_filters
from .models import Vacancy

class VacancyFilter(django_filters.FilterSet):
    salary_min = django_filters.NumberFilter(field_name="min_salary", lookup_expr="gte")
    salary_max = django_filters.NumberFilter(field_name="min_salary", lookup_expr="lte")
    location = django_filters.CharFilter(field_name="location", lookup_expr="icontains")
    category = django_filters.NumberFilter(field_name="category__id")  # ან category__slug თუ სლაგით გინდა
    vacancy_type = django_filters.CharFilter(field_name="vacancy_type", lookup_expr="iexact")  
    category_slug = django_filters.CharFilter(field_name="category__slug", lookup_expr="iexact")


    class Meta:
        model = Vacancy
        fields = ["location", "category","category_slug", "vacancy_type", "salary_min", "salary_max"]