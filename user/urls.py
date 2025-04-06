from django.contrib import admin
from django.urls import include, path

from user import views

urlpatterns = [
    path('', views.user, name='user'),
    path('create/',views.create_user, name='create_user'),
    path('update/<int:user_id>', views.update_user, name='update_user'),
    path('delete/<int:user_id>', views.delete_user, name='delete_user'),
    path('login/', views.login_user, name='login'),
    path('register/', views.register_user, name='register'),
    path('logout/',views.logout_user, name='logout')
]
