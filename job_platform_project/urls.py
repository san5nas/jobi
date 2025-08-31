from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView, SpectacularSwaggerView

from core.views import EmailTokenObtainPairView  # email-ის ველი JWT-ზე

urlpatterns = [
    path('admin/', admin.site.urls),

    # Core API
    path('api/', include('core.urls')),

    # DRF built-in login/logout (Browsable API)
    path('api-auth/', include('rest_framework.urls')),

    # JWT endpoints (ერთი ადგილი, პროექტის urls.py)
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),              # username+password
    path('api/token/email/', EmailTokenObtainPairView.as_view(), name='token_obtain_pair_email'),  # email+password
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # OpenAPI schema + docs
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/swagger/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('api/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
]
