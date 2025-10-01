# core/serializers_password_reset.py

from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.utils import timezone
from .models import PasswordResetPin

User = get_user_model()


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        from django.contrib.auth import get_user_model
        User = get_user_model()
        try:
            user = User.objects.get(email=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist")
        # ვტენით user ობიექტს context-ში
        self.context["user"] = user
        return value

    @property
    def validated_user(self):
        return self.context.get("user")


class PasswordResetConfirmSerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only=True)
    new_password2 = serializers.CharField(write_only=True)

    def validate(self, data):
        if data["new_password"] != data["new_password2"]:
            raise serializers.ValidationError("Passwords do not match")
        return data

    def save(self, **kwargs):
        user = self.context.get("user")
        if not user:
            raise serializers.ValidationError("User context missing")

        new_password = self.validated_data["new_password"]
        user.set_password(new_password)
        user.save()
        return user

class PasswordResetVerifyPinSerializer(serializers.Serializer):
    pin = serializers.CharField(max_length=6)

    def validate_pin(self, value):
        if not value.isdigit() or len(value) != 6:
            raise serializers.ValidationError("Invalid PIN format")

        from .models import PasswordResetPin
        reset_obj = PasswordResetPin.objects.filter(pin=value).first()
        if not reset_obj or not reset_obj.is_valid():
            raise serializers.ValidationError("Invalid or expired PIN")
        self.context["reset_obj"] = reset_obj
        return value

    @property
    def validated_reset(self):
        return self.context.get("reset_obj")
