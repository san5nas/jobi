from rest_framework import permissions


class ReadOnlyOrRole(permissions.BasePermission):
    def has_permission(self, request, view):
        # GET/HEAD/OPTIONS ყველას
        if request.method in permissions.SAFE_METHODS:
            return True
        # წერადი ქმედებები გამკაცრდეს ობიექტური ნებართვებით (ქვემოთ ViewSet-ებში)
        return False

class IsEmployer(permissions.BasePermission):
    def has_permission(self, request, view):
        return (
            request.user
            and request.user.is_authenticated
            and request.user.user_type == "employer"
        )

    def has_object_permission(self, request, view, obj):
        # EmployerProfile → პირდაპირ user ველია
        if request.method in permissions.SAFE_METHODS:
            return True

        if hasattr(obj, "user"):  # EmployerProfile
            return obj.user == request.user
        # Vacancy ან მსგავსი მოდელი სადაც employer ფიქსია
        if hasattr(obj, "employer"):
            return obj.employer.user == request.user
        return False


class IsAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.user_type == 'admin'

class IsJobSeeker(permissions.BasePermission):
    def has_permission(self, request, view):
        return (
            request.user
            and request.user.is_authenticated
            and request.user.user_type == "job_seeker"
        )

    def has_object_permission(self, request, view, obj):
        # SAFE_METHODS → ნებისმიერს შეუძლია წაკითხვა
        if request.method in permissions.SAFE_METHODS:
            return True

        # PATCH/PUT/DELETE → მხოლოდ საკუთარ პროფილზე
        return hasattr(obj, "user") and obj.user == request.user


class CanEditVacancy(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.employer.user == request.user

class CanUpdateApplicationStatus(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.vacancy.employer.user == request.user

class CanApproveVacancies(permissions.BasePermission):
    def has_permission(self, request, view):
        return bool(
            request.user and request.user.is_authenticated
            and request.user.has_perm("core.can_approve_vacancies")
        )