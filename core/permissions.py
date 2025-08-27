from rest_framework import permissions

class IsEmployer(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.user and request.user.is_authenticated and request.user.user_type == 'employer':
            return True
        return False

    def has_object_permission(self, request, view, obj):
        return obj.employer.user == request.user

class IsAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.user_type == 'admin'

class IsJobSeeker(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.user and request.user.is_authenticated and request.user.user_type == 'job_seeker':
            return True
        return False

    def has_object_permission(self, request, view, obj):
        # Allow read/update only on the user's own profile
        return obj.user == request.user

class CanEditVacancy(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.employer.user == request.user

class CanUpdateApplicationStatus(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.vacancy.employer.user == request.user
