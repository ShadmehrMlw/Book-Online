from django.urls import path, include
from rest_framework import routers
from .views import  *



app_name = "user_area"
router = routers.SimpleRouter()


urlpatterns = [
    path('', include(router.urls)),

    path('info/', AuthenticatedView.as_view(), name='info'),#send otp code that have no phone to registered if exsist say that phone is exists
    path('auth', CheckPhoneView.as_view(), name='auth'),#check are there a phone. if so send token and otp otherwise refer to info endpoint
    path('verify', VerifyCodeView.as_view(), name='verify'),
    path('logout', LogoutView.as_view(), name='logout'),

    path('password', CheckPasswordView.as_view(), name='password'),
    path('forgot-pass', ForgotPasswordView.as_view(), name='forgot_pass'),
    
    path('user', UserView.as_view(), name='user'),
    path('role', RoleView.as_view(), name='role'),
    path('city', CityView.as_view(), name='city'),
    path('province', ProvinceView.as_view(), name='city'),

   
]
