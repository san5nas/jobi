from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django import forms
from django.contrib.auth.forms import UserChangeForm, UserCreationForm
from django.contrib import messages
import json
from django.utils.safestring import mark_safe
from django import forms
from .models import LANGUAGE_LEVELS 

from .models import (
    User, EmployerProfile, Vacancy, Application, Service, PurchasedService,
    Invoice, Category, JobSeekerProfile, Language, WorkExperience, AdminProfile,
    MyVacancy,LanguageEntry,
    Education, JobSeekerLanguage, Skill,SkillEntry
)

from django.core.mail import send_mail
from .admin_forms import VacancyAdminForm

from django.core.exceptions import PermissionDenied
from django.utils import timezone
from django.db.models import Q
from .models import PurchasedService



LANGUAGE_LEVELS = [
    ("A1", "Beginner"),
    ("A2", "Elementary"),
    ("B1", "Intermediate"),
    ("B2", "Upper Intermediate"),
    ("C1", "Advanced"),
    ("C2", "Proficient"),
]



@admin.register(Language)
class LanguageAdmin(admin.ModelAdmin):
    search_fields = ("name",)   # საჭიროა autocomplete-ისთვის
    list_display = ("id", "name")

@admin.register(Skill)
class SkillAdmin(admin.ModelAdmin):
    list_display = ("id", "name")
    search_fields = ("name",)

    def get_model_perms(self, request):
        # ცარიელი dict → მოდელი არ გამოჩნდება მარცხენა მენიუში,
        # თუმცა რეგისტრირებულია და inline/autocomplete მუშაობს.
        return {}
# Custom User forms/admin
# =========================
class CustomUserCreationForm(UserCreationForm):
    full_name = forms.CharField(label="Full name", max_length=255, required=False)

    class Meta(UserCreationForm.Meta):
        model = User
        fields = ('username', 'email', 'user_type', 'full_name', 'first_name', 'last_name')

    def save(self, commit=True):
        user = super().save(commit=False)
        full_name = self.cleaned_data.get("full_name", "") or ""
        parts = full_name.split(' ', 1)
        user.first_name = parts[0] if parts and parts[0] else ""
        user.last_name = parts[1] if len(parts) > 1 else ""
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
        full_name = self.cleaned_data.get("full_name", "") or ""
        parts = full_name.split(' ', 1)
        user.first_name = parts[0] if parts and parts[0] else ""
        user.last_name = parts[1] if len(parts) > 1 else ""
        if commit:
            user.save()
        return user

@admin.register(User)
class CustomUserAdmin(UserAdmin):
    form = CustomUserChangeForm
    add_form = CustomUserCreationForm

    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal info', {'fields': ('full_name', 'email')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
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
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
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
        super().save_model(request, obj, form, change)


# User profile inlines for User admin
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
# Core simple admins
# =========================
@admin.register(AdminProfile)
class AdminProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'phone')
    search_fields = ('user__username', 'user__email', 'phone')

@admin.register(EmployerProfile)
class EmployerProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'company_name', 'is_approved_by_admin')
    list_filter = ('is_approved_by_admin',)
    search_fields = ('user__username', 'company_name')

# =========================
class EducationInline(admin.TabularInline):
    model = Education
    extra = 1
    fields = ('institution', 'degree', 'field', 'start_date', 'end_date', 'currently_studying')

class LanguageEntryInline(admin.TabularInline):
    model = LanguageEntry
    extra = 1
    fields = ('language', 'level')

class SkillEntryInline(admin.TabularInline):
    model = SkillEntry
    extra = 1
    fields = ('skill',)


class JobSeekerLanguageInline(admin.TabularInline):
    model = JobSeekerLanguage
    extra = 1
    autocomplete_fields = ('language',)


class PreferredVacancyInline(admin.TabularInline):
    model = Vacancy
    fields = ("title", "location", "employer", "category", "published_date", "is_published", "is_approved")
    readonly_fields = fields
    can_delete = False
    extra = 0
    verbose_name = "სასურველი ვაკანსია"
    verbose_name_plural = "სასურველი ვაკანსიები"
    show_change_link = True  # ღილაკი რედაქტირებისთვის, სურვილისამებრ

    def get_queryset(self, request):
        # ყველა ვაკანსია თუ არ არის parent განვსაზღვრავთ
        qs = super().get_queryset(request)
        if not hasattr(self, "parent_object") or not self.parent_object:
            return qs.none()

        categories = self.parent_object.preferred_categories.all()
        return qs.filter(
            category__in=categories,
            is_approved=True,
            is_published=True
        )

    def get_formset(self, request, obj=None, **kwargs):
        self.parent_object = obj  # ეს გვაძლევს parent-ს წვდომას
        return super().get_formset(request, obj, **kwargs)

@admin.register(JobSeekerProfile)
class JobSeekerProfileAdmin(admin.ModelAdmin):
    readonly_fields = ('user',)
    exclude = ('skills',)

    inlines = [
        WorkExperienceInline,
        EducationInline,
        LanguageEntryInline,
        SkillEntryInline,
    ]

    fieldsets = (
        (None, {'fields': ('user', 'cv', 'video_resume', 'diploma_upload')}),
        ('Preferences', {'fields': ('preferred_categories',)}),
    )

    # ✅ აქ ჩავამატეთ
    def has_view_permission(self, request, obj=None):
        if request.user.is_superuser:
            return True
        return super().has_view_permission(request, obj)

    def has_change_permission(self, request, obj=None):
        if request.user.is_superuser:
            return True
        return super().has_change_permission(request, obj)

    def has_add_permission(self, request):
        if request.user.is_superuser:
            return True
        return False  # მხოლოდ superuser-ს შეუძლია დამატება

    def has_module_permission(self, request):
        return request.user.is_superuser


# =========================
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

    def get_readonly_fields(self, request, obj=None):
        if request.user.is_superuser:
            return ()
        return ("job_seeker",)

    def get_exclude(self, request, obj=None):
        if request.user.is_superuser:
            return ()
        return ("job_seeker",)

    def save_model(self, request, obj, form, change):
        if not request.user.is_superuser:
            obj.job_seeker = request.user
        super().save_model(request, obj, form, change)

@admin.register(Vacancy)
class VacancyAdmin(admin.ModelAdmin):
    list_display  = ('title', 'employer', 'location', 'is_published', 'is_approved', 'published_date')
    list_filter   = ('is_published', 'is_approved', 'vacancy_type', 'category')
    search_fields = ('title', 'employer__company_name', 'location')
    inlines       = [ApplicationInline]
    actions       = ("approve_vacancies", "reject_vacancies")
    form = VacancyAdminForm

    def _can_approve(self, request):
        return request.user.is_superuser or request.user.has_perm("core.can_approve_vacancies")

    def get_readonly_fields(self, request, obj=None):
        # მხოლოდ დამმტკიცებელს ჰქონდეს is_approved-ის შეცვლა
        if self._can_approve(request):
            return ()
        return ('is_approved',)

    def get_queryset(self, request):
        qs = super().get_queryset(request).select_related('employer')
        if request.user.is_superuser or self._can_approve(request):
            return qs  # დამმტკიცებელი ხედავს ყველაფერს
        if getattr(request.user, "user_type", "") == "employer":
            return qs.filter(employer__user=request.user)
        if getattr(request.user, "user_type", "") == "job_seeker":
            return qs.filter(is_approved=True)
        return qs.none()

    @admin.action(description="Approve selected vacancies")
    def approve_vacancies(self, request, queryset):
        if not self._can_approve(request):
            self.message_user(request, "You don't have permission to approve.", level=messages.ERROR)
            return
        queryset.update(is_approved=True)

    @admin.action(description="Reject selected vacancies")
    def reject_vacancies(self, request, queryset):
        if not self._can_approve(request):
            self.message_user(request, "You don't have permission to reject.", level=messages.ERROR)
            return

        for vacancy in queryset:
            if not vacancy.rejection_reason:
                self.message_user(
                    request,
                    f"ვაკანსიას '{vacancy.title}' არ აქვს მითითებული უარყოფის მიზეზი. გთხოვთ შეავსოთ ველი 'rejection_reason'.",
                    level=messages.WARNING
                )
                continue

            # გიგზავნის მეილს დამსაქმებელს
            if vacancy.employer and vacancy.employer.user.email:
                send_mail(
                    subject="თქვენი ვაკანსია უარყოფილია",
                    message=(
                        f"თქვენი ვაკანსია '{vacancy.title}' უარყოფილია შემდეგი მიზეზით:\n\n"
                        f"{vacancy.rejection_reason}"
                    ),
                    from_email="no-reply@jobify.ge",
                    recipient_list=[vacancy.employer.user.email],
                    fail_silently=True
                )

            vacancy.is_approved = False
            vacancy.save()

        self.message_user(request, f"{queryset.count()} ვაკანსია უარყოფილია.", level=messages.INFO)

    def save_model(self, request, obj, form, change):
        # დამსაქმებელი რომ ქმნის admin-იდან — მის პროფილს მივაბათ
        if not request.user.is_superuser and getattr(request.user, "user_type", "") == "employer":
            obj.employer = getattr(request.user, "employerprofile", None)

        # Reject ჩეკბოქსის ლოგიკა
        if form.cleaned_data.get("reject"):
            obj.is_approved = False
            if obj.employer and obj.employer.user.email:
                send_mail(
                    subject="თქვენი ვაკანსია უარყოფილია",
                    message=(f"თქვენი ვაკანსია '{obj.title}' უარყოფილია შემდეგი მიზეზით:\n\n"
                             f"{obj.rejection_reason}"),
                    from_email="no-reply@jobify.ge",
                    recipient_list=[obj.employer.user.email],
                    fail_silently=True
                )

        # 🚩 ახალი ვაკანსიის შექმნისას მოვაკლოთ პაკეტიდან
        if not change and obj.employer:
            package = PurchasedService.objects.filter(
                user=obj.employer.user,
                is_active=True
            ).filter(
                Q(expiry_date__isnull=True) | Q(expiry_date__gte=timezone.now())
            ).order_by("-expiry_date").first()

            if not package:
                raise PermissionDenied("აქტიური პაკეტი არ აქვს და ვერ შექმნის ვაკანსიას.")

            if obj.is_premium:
                if package.remaining_premium <= 0:
                    raise PermissionDenied("დამსაქმებელს აღარ აქვს პრემიუმ ვაკანსიების ლიმიტი.")
                package.remaining_premium -= 1
            else:
                if package.remaining_standard <= 0:
                    raise PermissionDenied("დამსაქმებელს აღარ აქვს სტანდარტული ვაკანსიების ლიმიტი.")
                package.remaining_standard -= 1

            package.save()

        super().save_model(request, obj, form, change)

@admin.register(MyVacancy)
class MyVacancyAdmin(admin.ModelAdmin):
    list_display = ('title', 'location', 'is_published', 'published_date', 'category')
    list_filter = ('category',)
    inlines = [ApplicationInline]

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if request.user.is_superuser:
            return qs
        if request.user.is_authenticated and request.user.user_type == "employer":
            return qs.filter(employer__user=request.user)
        return qs.none()

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

@admin.register(Service)
class ServiceAdmin(admin.ModelAdmin):
    list_display = ("name", "price", "premium_limit", "standard_limit", "duration_days")
    def has_delete_permission(self, request, obj=None):
        return request.user.is_superuser
    
@admin.register(PurchasedService)
class PurchasedServiceAdmin(admin.ModelAdmin):
    list_display = ("user", "service", "is_active", "remaining_premium", "remaining_standard", "expiry_date")
    list_filter = ("is_active",)
    search_fields = ("user__username", "service__name")

    def save_model(self, request, obj, form, change):
        was_inactive = not obj.pk or not PurchasedService.objects.filter(pk=obj.pk, is_active=True).exists()
        super().save_model(request, obj, form, change)
        # თუ ახლა გახდა active და ადრე არ იყო active, გავუშვათ activate()
        if obj.is_active and was_inactive:
            obj.activate()

admin.site.register(Invoice)

