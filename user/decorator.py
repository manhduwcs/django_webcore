from textwrap import wrap
from django.shortcuts import redirect
from functools import wraps

from user.models import Role

def require_user_login(view_func):
    @wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        return view_func(request, *args, **kwargs)
    return wrapped_view

def admin_only(view_func):
    @wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        if not request.user.role == Role.ADMIN:
            return redirect('home')
        return view_func(request, *args, **kwargs)
    return wrapped_view