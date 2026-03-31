from django.urls import path

from . import views

app_name = "api"

urlpatterns = [
    path("investigations/", views.investigation_list, name="investigation-list"),
    path("investigations/create/", views.investigation_create, name="investigation-create"),
    path("investigations/<int:pk>/", views.investigation_detail, name="investigation-detail"),
    path("investigations/<int:pk>/status/", views.investigation_status, name="investigation-status"),
    path("community/", views.community_list, name="community-list"),
]
