from django.urls import path

from . import views

app_name = "sources"

urlpatterns = [
    path("", views.source_list, name="list"),
    path("health/", views.source_health, name="health"),
    path("<slug:slug>/", views.source_detail, name="detail"),
]
