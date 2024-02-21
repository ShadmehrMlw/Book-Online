
from django.contrib import admin
from django.urls import  re_path, include




urlpatterns = [
    re_path(r'^admin/', admin.site.urls),
    re_path(r'^api-auth/', include('rest_framework.urls')),
    re_path('api/', include('user_area.urls', namespace='user_area')),
]
