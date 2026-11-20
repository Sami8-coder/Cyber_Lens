from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm, PasswordChangeForm
from django.contrib.auth import update_session_auth_hash
from django.contrib import messages
from .forms import UserRegistrationForm, UserProfileForm, UserSettingsForm
from .models import UserProfile

def register_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard:index')

    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password'])
            user.save()

            # Update profile extra fields
            profile = user.profile
            profile.organization = form.cleaned_data.get('organization', '')
            profile.job_title = form.cleaned_data.get('job_title', '')
            profile.save()

            login(request, user)
            messages.success(request, f"Welcome to CyberLens, {user.username}! Your account has been initialized.")
            return redirect('dashboard:index')
        else:
            messages.error(request, "Please correct the errors below.")
    else:
        form = UserRegistrationForm()

    return render(request, 'accounts/register.html', {'form': form})


def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard:index')

    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            messages.success(request, f"Welcome back, {user.first_name or user.username}!")
            next_url = request.GET.get('next')
            if next_url:
                return redirect(next_url)
            return redirect('dashboard:index')
        else:
            messages.error(request, "Invalid username or password.")
    else:
        form = AuthenticationForm()

    return render(request, 'accounts/login.html', {'form': form})


def logout_view(request):
    logout(request)
    messages.info(request, "You have been successfully logged out.")
    return redirect('core:home')


@login_required
def profile_view(request):
    user = request.user
    profile = user.profile

    if request.method == 'POST':
        form = UserProfileForm(request.POST, instance=profile)
        first_name = request.POST.get('first_name', '').strip()
        last_name = request.POST.get('last_name', '').strip()
        email = request.POST.get('email', '').strip()

        if form.is_valid():
            user.first_name = first_name
            user.last_name = last_name
            if email:
                user.email = email
            user.save()
            form.save()
            messages.success(request, "Your profile has been updated successfully.")
            return redirect('accounts:profile')
        else:
            messages.error(request, "Failed to update profile. Please verify your inputs.")
    else:
        initial = {
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email,
        }
        form = UserProfileForm(instance=profile, initial=initial)

    return render(request, 'accounts/profile.html', {
        'form': form,
        'profile': profile,
    })


@login_required
def settings_view(request):
    user = request.user
    profile = user.profile

    if request.method == 'POST':
        form = UserSettingsForm(request.POST, instance=profile)
        if form.is_valid():
            form.save()
            messages.success(request, "Scan settings updated successfully.")
            return redirect('accounts:settings')
    else:
        form = UserSettingsForm(instance=profile)

    return render(request, 'accounts/settings.html', {
        'form': form,
        'profile': profile,
    })


@login_required
def change_password_view(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            messages.success(request, "Your password was successfully updated!")
            return redirect('accounts:profile')
        else:
            messages.error(request, "Please correct the password errors below.")
    else:
        form = PasswordChangeForm(request.user)

    return render(request, 'accounts/password_change.html', {'form': form})


@login_required
def regenerate_api_key_view(request):
    if request.method == 'POST':
        new_key = request.user.profile.generate_api_key()
        messages.success(request, f"Generated new CyberLens API Key: {new_key}")
    return redirect('accounts:settings')
