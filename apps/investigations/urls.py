from django.urls import path

from . import views

app_name = "investigations"

urlpatterns = [
    path("", views.investigation_list, name="list"),
    path("new/", views.investigation_new, name="new"),
    path("<int:pk>/", views.investigation_detail, name="detail"),
]
