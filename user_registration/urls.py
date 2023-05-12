from django.urls import path
from . import views

app_name = 'user_registration'


urlpatterns = [
    path('', views.index, name='index'),
    path('register/', views.register, name='register'),
    path('user_login/', views.user_login, name='user_login'),
    path('user_logout/', views.user_logout, name='user_logout'),
    path('user_profile/<int:id>/', views.user_profile, name="user_profile"),
    path('change_password/<int:id>/', views.change_password, name='change_password'),
    path('upload_profile_image/<int:id>/', views.upload_profile_image, name='upload_profile_image'),
]


