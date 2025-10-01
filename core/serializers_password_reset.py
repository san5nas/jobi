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
    pin = serializers.CharField(max_length=6)
    new_password = serializers.CharField(write_only=True)
    new_password2 = serializers.CharField(write_only=True)

    def validate(self, data):
        if data["new_password"] != data["new_password2"]:
            raise serializers.ValidationError("Passwords do not match")
        return data

    def validate_pin(self, value):
        if not value.isdigit() or len(value) != 6:
            raise serializers.ValidationError("Invalid PIN format")
        return value

    def save(self, **kwargs):
        pin = self.validated_data["pin"]
        new_password = self.validated_data["new_password"]

        # ვპოულობთ PIN-ს DB-ში
        reset_obj = PasswordResetPin.objects.filter(pin=pin).first()
        if not reset_obj or not reset_obj.is_valid():
            raise serializers.ValidationError({"pin": "Invalid or expired PIN"})

        user = reset_obj.user
        user.set_password(new_password)
        user.save()
        reset_obj.delete()  # ერთხელ გამოყენების შემდეგ წავშალოთ
        return user
