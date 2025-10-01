# core/views_password_reset.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from django.core.mail import send_mail
from .models import PasswordResetPin
from .serializers_password_reset import PasswordResetRequestSerializer, PasswordResetConfirmSerializer
from django.core.signing import TimestampSigner, BadSignature, SignatureExpired
from django.contrib.auth import get_user_model


User = get_user_model()
signer = TimestampSigner()


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



class PasswordResetVerifyPinView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        from .serializers_password_reset import PasswordResetVerifyPinSerializer
        serializer = PasswordResetVerifyPinSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        reset_obj = serializer.validated_reset
        user = reset_obj.user

        # წავშალოთ PIN, ერთჯერადი იყოს
        reset_obj.delete()

        # ვაგენერირებთ reset_token-ს
        token = signer.sign(user.id)

        # ვასვამთ ქუქიში
        response = Response({"detail": "PIN is valid"})
        response.set_cookie(
            key="reset_token",
            value=token,
            httponly=True,
            secure=False,   # HTTPS-ზე გადაიყვანე True
            samesite="None",
            max_age=15 * 60  # 15 წუთი
        )
        return response

class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        reset_token = request.COOKIES.get("reset_token")
        if not reset_token:
            return Response({"error": "Missing reset_token cookie"}, status=400)

        try:
            user_id = signer.unsign(reset_token, max_age=60*15)  # 15 წუთი ვადა
            user = User.objects.get(id=user_id)
        except (BadSignature, SignatureExpired, User.DoesNotExist):
            return Response({"error": "Invalid or expired token"}, status=400)

        serializer = PasswordResetConfirmSerializer(
            data=request.data,
            context={"user": user}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        # პაროლის შეცვლის შემდეგ წავშალოთ reset_token ქუქი
        response = Response({"detail": "Password reset successful"})
        response.delete_cookie("reset_token")
        return response
