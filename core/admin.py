from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import (
    User, EmployerProfile, Vacancy, Application, Service, PurchasedService,
    Invoice, Category, JobSeekerProfile, Language, WorkExperience, AdminProfile
)
from django import forms
import json

class WorkExperienceInline(admin.TabularInline):
    model = WorkExperience
    extra = 1

class JobSeekerProfileInline(admin.StackedInline):
    model = JobSeekerProfile
    can_delete = False
    verbose_name_plural = 'Job Seeker Profile'
    # nested inline Django-ს არ უჭერს მხარს, ამიტომ ეს ხაზი შეგვიძლია არ გამოვიყენოთ:
    # inlines = [WorkExperienceInline]

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
    list_display = ('username', 'email', 'user_type', 'is_staff')
    list_filter = ('user_type', 'is_staff')
    fieldsets = UserAdmin.fieldsets + (
        ('Custom Fields', {'fields': ('user_type',)}),
    )

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
