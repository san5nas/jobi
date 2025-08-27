from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model

UserModel = get_user_model()

class UsernameOrEmailBackend(ModelBackend):
    """
    Custom backend: user can login with username or email
    """
    def authenticate(self, request, username=None, password=None, **kwargs):
        if username is None:
            username = kwargs.get(UserModel.USERNAME_FIELD)

        try:
            # Try username first
            user = UserModel.objects.get(username=username)
        except UserModel.DoesNotExist:
            try:
                # If not found, try email
                user = UserModel.objects.get(email=username)
            except UserModel.DoesNotExist:
                return None

        if user.check_password(password) and self.user_can_authenticate(user):
            return user
        return None
