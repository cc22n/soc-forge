from django.urls import path

from . import views

app_name = "sources"

urlpatterns = [
    path("", views.source_list, name="list"),
    path("<slug:slug>/", views.source_detail, name="detail"),
]
