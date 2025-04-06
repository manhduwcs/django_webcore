import re
from tkinter import Widget
from wsgiref.validate import validator
from django import forms
from django.shortcuts import get_object_or_404
from django.contrib.auth.hashers import make_password
from django.contrib.auth.forms import AuthenticationForm
from django.core.validators import (
    MaxLengthValidator,
    MinLengthValidator,
    validate_slug,
    validate_email,
    RegexValidator,
)
from user.models import User
from user.models import User
from django.contrib.auth.forms import PasswordChangeForm

class FormLogin(AuthenticationForm):
    username = forms.CharField(
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "placeholder": "Enter username",
            }
        ),
        validators=[MaxLengthValidator(50), MinLengthValidator(5), validate_slug],
    )

    password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control",
                "placeholder": "Enter password",
            }
        ),
        validators=[MaxLengthValidator(30), MinLengthValidator(8)],
    )

class FormRegister(forms.ModelForm):
    re_password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control mt-1",
                "placeholder": "Re-enter password",
            }
        ),
        label="Confirm Password",
    )
    
    password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control mt-1",
                "placeholder": "Password",
            }
        ),
        label="Enter Password",
        validators=[
            MaxLengthValidator(100), MinLengthValidator(8)
        ]
    )

    class Meta:
        model = User
        fields = ["username", "fullname", "phone", "email", "password", "re_password"]
        widgets = {
            "username": forms.TextInput(
                attrs={
                    "class": "form-control mt-1",
                    "placeholder": "Username",
                }
            ),
            "fullname": forms.TextInput(
                attrs={
                    "class": "form-control mt-1",
                    "placeholder": "Full Name",
                }
            ),
            "phone": forms.TextInput(
                attrs={
                    "class": "form-control mt-1",
                    "placeholder": "Phone",
                }
            ),
            "email": forms.EmailInput(
                attrs={
                    "class": "form-control mt-1",
                    "placeholder": "Email",
                }
            ),
        }

    def clean(self):
        cleaned = super().clean()
        password = cleaned.get("password")
        re_password = cleaned.get("re_password")
        if password and re_password and password != re_password:
            raise forms.ValidationError("Passwords do not match!")
        return cleaned

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class FormUpdateUser(forms.ModelForm):
    re_password = forms.CharField(
        required=False,
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control mt-1",
                "placeholder": "Re-enter password",
            }
        ),
        label="Confirm Password",
    )
    
    password = forms.CharField(
        required=False,
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control mt-1",
                "placeholder": "Password",
            }
        ),
        label="Enter Password",
        validators=[
            MaxLengthValidator(100), MinLengthValidator(8)
        ]
    )

    class Meta:
        model = User
        fields = ["username", "fullname", "phone", "email", "password", "re_password"]
        widgets = {
            "username": forms.TextInput(
                attrs={
                    "class": "form-control mt-1",
                    "placeholder": "Username",
                }
            ),
            "fullname": forms.TextInput(
                attrs={
                    "class": "form-control mt-1",
                    "placeholder": "Full Name",
                }
            ),
            "phone": forms.TextInput(
                attrs={
                    "class": "form-control mt-1",
                    "placeholder": "Phone",
                }
            ),
            "email": forms.EmailInput(
                attrs={
                    "class": "form-control mt-1",
                    "placeholder": "Email",
                }
            ),
        }

    def clean(self):
        cleaned = super().clean()
        password = cleaned.get("password")
        re_password = cleaned.get("re_password")
        if password and re_password and password != re_password:
            raise forms.ValidationError("Passwords do not match!")
        return cleaned

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        self.user = kwargs.pop("user",None)
        if self.user:
            self.fields['username'].initial = self.user.username
            self.fields['fullname'].initial = self.user.fullname
            self.fields['phone'].initial = self.user.phone
            self.fields['email'].initial = self.user.email

class FormCreateUser(forms.ModelForm):
    re_password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control mt-1",
                "placeholder": "Re-enter password",
            }
        ),
        label="Confirm Password",
    )
    
    password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control mt-1",
                "placeholder": "Password",
            }
        ),
        label="Enter Password",
        validators=[
            MaxLengthValidator(100), MinLengthValidator(8)
        ]
    )

    class Meta:
        model = User
        fields = ["username", "fullname", "phone", "email", "password", "re_password"]
        widgets = {
            "username": forms.TextInput(
                attrs={
                    "class": "form-control mt-1",
                    "placeholder": "Username",
                }
            ),
            "fullname": forms.TextInput(
                attrs={
                    "class": "form-control mt-1",
                    "placeholder": "Full Name",
                }
            ),
            "phone": forms.TextInput(
                attrs={
                    "class": "form-control mt-1",
                    "placeholder": "Phone",
                }
            ),
            "email": forms.EmailInput(
                attrs={
                    "class": "form-control mt-1",
                    "placeholder": "Email",
                }
            ),
        }

    def clean(self):
        cleaned = super().clean()
        password = cleaned.get("password")
        re_password = cleaned.get("re_password")
        if password and re_password and password != re_password:
            raise forms.ValidationError("Passwords do not match!")
        return cleaned

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)