from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import (
    User, EmployerProfile, Vacancy, Application, Service, PurchasedService,
    Invoice, Category, JobSeekerProfile, Language, WorkExperience, AdminProfile
)
from django import forms
from django.contrib.auth.forms import UserChangeForm, UserCreationForm
from .models import MyVacancy
from django.urls import path
from django.shortcuts import redirect
from django.utils.text import slugify
# --- ნაბიჯი 1: მორგებული ფორმები ---
class CustomUserCreationForm(UserCreationForm):
    full_name = forms.CharField(label="Full name", max_length=255, required=False)

    class Meta(UserCreationForm.Meta):
        model = User
        fields = ('username', 'email', 'user_type', 'full_name', 'first_name', 'last_name')

    def save(self, commit=True):
        user = super().save(commit=False)
        full_name = self.cleaned_data.get("full_name", "")
        if full_name:
            name_parts = full_name.split(' ', 1)
            user.first_name = name_parts[0]
            if len(name_parts) > 1:
                user.last_name = name_parts[1]
            else:
                user.last_name = ""
        else:
            user.first_name = ""
            user.last_name = ""
            
        if commit:
            user.save()
        return user

class CustomUserChangeForm(UserChangeForm):
    full_name = forms.CharField(label="Full name", max_length=255, required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance:
            self.fields['full_name'].initial = f"{self.instance.first_name} {self.instance.last_name}".strip()

    def save(self, commit=True):
        user = super().save(commit=False)
        full_name = self.cleaned_data.get("full_name", "")
        if full_name:
            name_parts = full_name.split(' ', 1)
            user.first_name = name_parts[0]
            if len(name_parts) > 1:
                user.last_name = name_parts[1]
            else:
                user.last_name = ""
        else:
            user.first_name = ""
            user.last_name = ""

        if commit:
            user.save()
        return user

# UserAdmin-ის სტანდარტული fieldsets-ის კოპირება და მოდიფიცირება
MyUserAdminFieldsets = list(UserAdmin.fieldsets)
permissions_fields = list(MyUserAdminFieldsets[2][1]['fields'])
permissions_fields.remove('is_staff') 
MyUserAdminFieldsets[2][1]['fields'] = tuple(permissions_fields)
MyUserAdminFieldsets[2] = MyUserAdminFieldsets[2]

class WorkExperienceInline(admin.TabularInline):
    model = WorkExperience
    extra = 1

class JobSeekerProfileInline(admin.StackedInline):
    model = JobSeekerProfile
    can_delete = False
    verbose_name_plural = 'Job Seeker Profile'

class EmployerProfileInline(admin.StackedInline):
    model = EmployerProfile
    can_delete = False
    verbose_name_plural = 'Employer Profile'

class AdminProfileInline(admin.StackedInline):
    model = AdminProfile
    can_delete = False
    verbose_name_plural = 'Admin Profile'

@admin.register(User)
class CustomUserAdmin(UserAdmin):
    form = CustomUserChangeForm
    add_form = CustomUserCreationForm
    
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal info', {'fields': ('full_name', 'email')}),
        ('Permissions', {'fields': ('is_active', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
        ('Custom Fields', {
            'fields': (
                'user_type',
                'phone_number',
                'is_verified',
                'google_access_token',
                'google_refresh_token',
                'google_token_expiry',
            )
        }),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'user_type', 'full_name', 'password1', 'password2')
        }),
        ('Permissions', {'fields': ('is_active', 'is_superuser', 'groups', 'user_permissions')}),
    )

    list_display = ('username', 'email', 'user_type', 'is_active', 'is_staff')
    list_filter = ('user_type', 'is_active', 'is_staff')

    def get_inline_instances(self, request, obj=None):
        if not obj:
            return []
        if obj.user_type == 'job_seeker':
            return [JobSeekerProfileInline(self.model, self.admin_site)]
        elif obj.user_type == 'employer':
            return [EmployerProfileInline(self.model, self.admin_site)]
        elif obj.user_type == 'admin':
            return [AdminProfileInline(self.model, self.admin_site)]
        return []

    def save_model(self, request, obj, form, change):
        obj.is_staff = obj.is_active
        super().save_model(request, obj, form, change)

@admin.register(AdminProfile)
class AdminProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'phone')
    search_fields = ('user__username', 'user__email', 'phone')

@admin.register(EmployerProfile)
class EmployerProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'company_name', 'is_approved_by_admin')
    list_filter = ('is_approved_by_admin',)
    search_fields = ('user__username', 'company_name')

@admin.register(JobSeekerProfile)
class JobSeekerProfileAdmin(admin.ModelAdmin):
    list_display = ('user',)
    inlines = [WorkExperienceInline]


class ApplicationInline(admin.TabularInline):
    model = Application
    extra = 0
    readonly_fields = ('job_seeker', 'cv', 'cover_letter', 'status', 'applied_at', 'interview_start', 'interview_end')
    can_delete = False
    verbose_name_plural = "განაცხადები"

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if request.user.is_superuser:
            return qs
        if getattr(request.user, "user_type", "") == "employer":
            return qs.filter(vacancy__employer__user=request.user)
        return qs.none()

@admin.register(Application)
class ApplicationAdmin(admin.ModelAdmin):
    list_display = ("id", "vacancy", "job_seeker", "status", "applied_at", "interview_start", "interview_end")
    search_fields = ("vacancy__title", "job_seeker__username", "job_seeker__email")
    list_filter = ("status",)


@admin.register(Vacancy)
class VacancyAdmin(admin.ModelAdmin):
    list_display = ('title', 'employer', 'location', 'is_published', 'published_date')
    list_filter = ('is_published', 'vacancy_type', 'category')
    search_fields = ('title', 'employer__company_name', 'location')
    inlines = [ApplicationInline]

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if request.user.is_superuser:
            return qs
        if request.user.user_type == "employer":
            return qs  # ❗ ხედავს ყველა ვაკანსიას
        if request.user.user_type == "job_seeker":
            return qs.filter(is_published=True)
        return qs.none()
    def get_inline_instances(self, request, obj=None):
        if not obj:
            return []
        if request.user.is_superuser or request.user.user_type == "employer":
            return super().get_inline_instances(request, obj)
        return []


@admin.register(MyVacancy)
class MyVacancyAdmin(admin.ModelAdmin):
    list_display = ('title', 'location', 'is_published', 'published_date', 'category')
    list_filter = ('category',)
    inlines = [ApplicationInline]

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if request.user.is_superuser:
            return qs
        if request.user.user_type == "employer":
            return qs.filter(employer__user=request.user)
        return qs.none()

    def category_view_factory(self, category):
        def view(request):
            request.GET = request.GET.copy()
            request.GET['category__id__exact'] = str(category.id)
            return self.changelist_view(request)
        return view

    def get_model_perms(self, request):
        if request.user.is_superuser or (request.user.is_authenticated and request.user.user_type == "employer"):
            return {"add": True, "change": True, "delete": False, "view": True}
        return {}

    def has_view_permission(self, request, obj=None):
        return request.user.is_superuser or (request.user.is_authenticated and request.user.user_type == "employer")

    def has_module_permission(self, request):
        return request.user.is_superuser or (request.user.is_authenticated and request.user.user_type == "employer")

@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ("name", "slug")
    search_fields = ("name", "slug")
    prepopulated_fields = {"slug": ("name",)}  


admin.site.register(Service)
admin.site.register(PurchasedService)
admin.site.register(Invoice)
