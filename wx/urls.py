from django.urls import path
from rest_framework.routers import DefaultRouter

from .views import LoginView, BindView, wxLogInCallbackView, webLoginView, webLoginCallback

urlpatterns = [
    path('login/', LoginView.as_view(), name='wxLogin'),
    path('bind/', BindView.as_view(), name='wxBind'),
    path('bind/callbaack/', wxLogInCallbackView, name='wxBindCallback'),

    path('weblogin/', webLoginView, name='webLogin'),
    path('weblogin/callback/', webLoginCallback, name='webLoginCallback'),
]
