import re
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from home import admin
from user.forms import FormCreateUser, FormLogin, FormRegister, FormUpdateUser
from django.contrib.auth.forms import AuthenticationForm
from user.models import User
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from user.decorator import require_user_login, admin_only

# User view.
@require_user_login
@admin_only
def user(request):
    # minus "-" : descending order.
    users = User.objects.order_by('-user_id')
    return render(request, 'user/index.html', {'users':users})

def logout_user(request):
    logout(request)
    return redirect('home')

# def login_user(request):
#     if request.method=='POST':
#         form = FormLogin(request.POST)
#         if form.is_valid():
#             username = form.cleaned_data.get('username')
#             password = form.cleaned_data.get('password')
#             user = authenticate(request=request, username=username, password=password)

#             if user is not None:
#                 login(request=request, user=user)
#                 return redirect('home')
#             else:
#                 messages.error(request,'Invalid form !')
#                 form = FormLogin(request.POST)
#     else:
#         messages.error(request,'Not post method !')
#         form = FormLogin()
#     return render(request, 'user/auth/login.html', {'form':form})

def login_user(request):
    if request.method=='GET':
        form = FormLogin()
        return render(request, 'user/auth/login.html', {'form':form, 'err_message':''})
    
    if request.method=='POST':
        form = FormLogin(request.POST)
    
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request=request, username=username, password=password)

        if user is None:
            message='Wrong username or password. Try again !'
            return render(request, 'user/auth/login.html', {'form':form, 'err_message':message})

        if user is not None:
            login(request=request, user=user)
            return redirect('home')
        
        else:
            message='Invalid username or password input !'
            form = FormLogin(request.POST)
    else:
        message='This is not a POST method. What is this bug ?'
        form = FormLogin()
    return render(request, 'user/auth/login.html', {'form':form, 'err_message':message})

def register_user(request):
    if request.method=='POST':
        form = FormRegister(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.password = make_password(user.password)
            user.save()
            login(request, user)
            return redirect(reverse('home'))
        else:
            form = FormRegister(request.POST)
    else:
        form = FormRegister()
    return render(request, 'user/auth/register.html', {'form':form})
                

# normal approach : get the pre-saving user instance by commit=False,
# then modify this user, then save()
@require_user_login
@admin_only
def create_user(request):
    if(request.method=='POST'):
        form = FormCreateUser(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            password = form.cleaned_data.get('password')
            user.password = make_password(password=password)
            user.save()
            return redirect('user')
    else:
        form = FormCreateUser()
    return render(request, 'user/create-user.html', {'form':form})

@require_user_login
@admin_only
def update_user(request, user_id):
    user = get_object_or_404(User, user_id = user_id)
    old_password = user.password
    if request.method=="POST":
        form = FormUpdateUser(request.POST, instance=user)
        if form.is_valid():
            # Always use cleaned_data to retrieve the actual form input's value.
            # If you use another way (fields.get), you may get the CharField, not the value
            username = form.cleaned_data.get('username') 
            password = form.cleaned_data.get('password')
            user = form.save(commit=False)
            if not username or not password:
                user.password = old_password
            else:
                user.password = make_password(password=password)
            user.save()
            return redirect('user')
    else:
        form = FormUpdateUser(instance=user)
    return render(request, 'user/update-user.html', {'form':form, 'user':user})

@require_user_login
@admin_only
def delete_user(request, user_id):
    user = get_object_or_404(User, user_id = user_id)
    if request.method=='POST':
        if user:
            user.delete()
            return redirect('user')
    return redirect('user')
