from django.urls import path
from rest_framework.routers import DefaultRouter

from .views import LoginView, BindView, wxLogInCallbackView

urlpatterns = [
    path('login/', LoginView.as_view(), name='wxlogin'),
    path('bind/', BindView.as_view(), name='wxbind'),
    path('bind/callbaack/', wxLogInCallbackView, name='wxbindcallback')
]
