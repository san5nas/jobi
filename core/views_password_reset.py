# core/views_password_reset.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from django.core.mail import send_mail
from .models import PasswordResetPin
from .serializers_password_reset import PasswordResetRequestSerializer, PasswordResetConfirmSerializer


class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_user   # ✔️ ახლა იმუშავებს
        reset_pin = PasswordResetPin.create_for_user(user)

        send_mail(
            subject="🔐 Password Reset Code",
            message=f"Your password reset PIN is: {reset_pin.pin}\nValid for 15 minutes.",
            from_email="no-reply@jobify.ge",
            recipient_list=[user.email],
        )

        return Response({"detail": "PIN sent to email"})

class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"detail": "Password reset successful"})
