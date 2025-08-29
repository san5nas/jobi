from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView, SpectacularSwaggerView

# NEW: email-ით JWT ლოგინი
from core.views import EmailTokenObtainPairView

urlpatterns = [
    path('admin/', admin.site.urls),

    # API apps
    path('api/', include('core.urls')),

    # JWT (username+password – default)
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    # JWT (email+password – ახალი)
    path('api/token/email/', EmailTokenObtainPairView.as_view(), name='token_obtain_pair_email'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # OpenAPI schema + UIs
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/swagger/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('api/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
]
