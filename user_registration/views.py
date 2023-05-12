from django.shortcuts import get_object_or_404, render, redirect
from .forms import UserForm, UserInfoForm

from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.http import HttpResponseRedirect, HttpResponse
from django.urls import reverse
from django.contrib.auth.decorators import login_required

from django.contrib.auth.models import User
from .models import UserInfo
from django.contrib.auth.forms import PasswordChangeForm


from django.contrib import messages


# Create your views here.
"""This function renders homepage"""
def index(request):
    return render(request, "user_registration/index.html")


"""This function registers the user."""
def register(request):
    registered = False

    if request.method == "POST":
        user_form = UserForm(data=request.POST)
        info_form = UserInfoForm(data=request.POST)

        if user_form.is_valid() and info_form.is_valid():
            user = user_form.save()
            user.set_password(user.password)
            user.save()

            info = info_form.save(commit=False)  # Shanka
            info.user = user

            if "profile_image" in request.FILES:
                info.profile_image = request.FILES["profile_image"]

            info.save()

            registered = True
            return redirect(reverse('user_registration:user_login'))

        else:
            print(user_form.errors, info_form.errors)
    else:
        user_form = UserForm()
        info_form = UserInfoForm()

    return render(
        request,
        "user_registration/register.html",
        {"user_form": user_form, "info_form": info_form, "registered": registered},
    )


"""This function logs in"""
def user_login(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(username=username, password=password)

        if user:
            if user.is_active:
                login(request, user)
                return HttpResponseRedirect(reverse("user_registration:index"))
            else:
                return HttpResponse("Account is not active")
        else:
            return HttpResponse("Invalid login detail.")
    else:
        return render(request, "user_registration/login.html")


"""This function logs out"""
@login_required
def user_logout(request):
    logout(request)
    return HttpResponseRedirect(reverse("user_registration:index"))


"""This function renders profile"""
@login_required
def user_profile(request, id):
    try:
        user = User.objects.get(id=id)
        user_info = UserInfo.objects.get(user=user)
        return render(
            request,
            "user_registration/user_profile.html",
            {"user": user, "user_info": user_info},
        )
    except UserInfo.DoesNotExist:
        return redirect("user_registration:user_login")


"""This function updates the password"""
@login_required
def change_password(request, id):
    id = request.user.id
    if request.method == "POST":
        password_form = PasswordChangeForm(request.user, request.POST)
        if password_form.is_valid():
            user = password_form.save()
            update_session_auth_hash(request, user)
            return redirect("user_registration:user_profile", id)
    else:
        password_form = PasswordChangeForm(request.user)
    return render(
        request,
        "user_registration/change_password.html",
        {"password_form": password_form},
    )


"""This function uploads images"""
def upload_profile_image(request, id):
    user = get_object_or_404(User, id=id)
    try:
        user_info = UserInfo.objects.get(user=user)
    except UserInfo.DoesNotExist:
        user_info = UserInfo(user=user)
        user_info.save()
    if request.method == 'POST':
        form = UserInfoForm(request.POST, request.FILES, instance=user_info)
        if form.is_valid():
            form.save()
            return redirect('user_registration:user_profile', id=id)
    else:
        form = UserInfoForm(instance=user_info)
    return render(request, 'user_registration/upload_profile_image.html', {'form':form})
   

