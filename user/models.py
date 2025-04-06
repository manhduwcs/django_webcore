from pyexpat import model
from typing import Required
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager

class Role(models.TextChoices):
    ADMIN = "Admin", "Admin"
    USER = "User", "User"
    STAFF = "Staff", "Staff"
    MODERATOR = "Moderator", "Moderator"

class UserManager(BaseUserManager):
    def create_user(self, username, fullname, phone, email, password=None):
        if not username:
            raise ValueError('The Username field must be set')
        if not fullname:
            raise ValueError('The Fullname field must be set')
        if not phone:
            raise ValueError('The Phone field must be set')
        if not email:
            raise ValueError('The Email field must be set')
        if not password:
            raise ValueError('The Password field must be set')
        email = self.normalize_email(email)
        user = self.model(
            username=username, 
            fullname=fullname, 
            phone=phone, 
            email=email)
        user.set_password(password) 
        user.save(using=self._db)
        return user
    
class User(AbstractBaseUser):
    user_id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=70, null=False, blank=False, unique=True)
    fullname = models.CharField(max_length=70, null=False, blank=True)
    phone = models.CharField(max_length=20, unique=True)
    email = models.CharField(max_length=50, unique=True)
    password = models.CharField(max_length=128)
    role = models.CharField(max_length=20, null=False, blank=False,editable=True, choices=Role.choices, default=Role.USER)

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['fullname', 'email', 'phone']
    objects = UserManager()
    def __str__(self):
        return f"{self.username} - {self.phone}"

