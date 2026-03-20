from django.urls import path

from . import views

app_name = "community"

urlpatterns = [
    path("", views.community_search, name="search"),
    path("<int:pk>/", views.community_detail, name="detail"),
    path("share/<int:investigation_pk>/", views.share_investigation, name="share"),
    path("vote/<int:result_pk>/<str:vote_type>/", views.community_vote, name="vote"),
    path("<int:ci_pk>/note/", views.community_add_note, name="add_note"),
]