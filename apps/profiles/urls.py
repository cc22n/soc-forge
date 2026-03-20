from django.urls import path

from . import views

app_name = "profiles"

urlpatterns = [
    path("", views.profile_list, name="list"),
    path("create/", views.profile_create, name="create"),
    path("<int:pk>/", views.profile_detail, name="detail"),
    path("<int:pk>/sources/", views.profile_edit_sources, name="edit_sources"),
    path("<int:pk>/fields/", views.profile_edit_fields, name="edit_fields"),
    path("<int:pk>/delete/", views.profile_delete, name="delete"),
    path("<int:pk>/clone/", views.profile_clone, name="clone"),
]
