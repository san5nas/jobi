from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import (
    User, EmployerProfile, Vacancy, Application, Service, PurchasedService,
    Invoice, Category, JobSeekerProfile, Language, WorkExperience, AdminProfile
)
from django import forms
import json
from django.contrib.auth.forms import UserChangeForm, UserCreationForm

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
    # --- ნაბიჯი 2: მორგებული ფორმების გამოყენება ---
    form = CustomUserChangeForm
    add_form = CustomUserCreationForm
    
    # fieldsets-ის გადაწერა, რომ ჩანდეს მხოლოდ საჭირო ველები
    # ვაშორებთ დუბლიკატებს და ვაერთიანებთ ჩვენს მორგებულ ველებს
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal info', {'fields': ('full_name', 'email')}),
        ('Permissions', {'fields': ('is_active', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
        ('Custom Fields', {'fields': ('user_type', 'phone_number', 'is_verified')}),
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
        """
        ავტომატურად რთავს is_staff-ს, როდესაც is_active მონიშნულია.
        ეს ლოგიკა ვრცელდება ყველა მომხმარებელზე.
        """
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

class VacancyInline(admin.TabularInline):
    model = Vacancy
    extra = 0

@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ('name',)
    search_fields = ('name',)
    inlines = [VacancyInline]

admin.site.register(Vacancy)
admin.site.register(Application)
admin.site.register(Service)
admin.site.register(PurchasedService)
admin.site.register(Invoice)
