from django.urls import path

from . import views

app_name = "users"

urlpatterns = [
    path("", views.home, name="home"),
    path("dashboard/", views.dashboard, name="dashboard"),
    path("auth/register/", views.register, name="register"),
]
