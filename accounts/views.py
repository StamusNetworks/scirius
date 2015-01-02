"""
Copyright(C) 2014, Stamus Networks
Written by Eric Leblond <eleblond@stamus-networks.com>

This file is part of Scirius.

Scirius is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Scirius is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Scirius.  If not, see <http://www.gnu.org/licenses/>.
"""

from django.shortcuts import redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.forms import PasswordChangeForm, UserCreationForm
from django.conf import settings
from django.contrib.auth.models import User

from scirius.utils import scirius_render, scirius_listing
from forms import LoginForm, UserSettingsForm, NormalUserSettingsForm
from models import SciriusUser

def loginview(request, target):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(username=username, password=password)
        if user is not None:
            if user.is_active:
                login(request, user)
                return redirect("/" + target)
            else:
                form = LoginForm()
                context = { 'form': form, 'error': 'Disabled account' }
                return scirius_render(request, 'accounts/login.html', context)
        else:
            form = LoginForm()
            context = { 'form': form, 'error': 'Invalid login' }
            return scirius_render(request, 'accounts/login.html', context)
    else:
        form = LoginForm()
        context = { 'form': form }
        return scirius_render(request, 'accounts/login.html', context)


def editview(request, action):
    if request.user.is_authenticated():
        if request.method == 'POST':
            context = { 'action': 'User settings' }
            orig_superuser = request.user.is_superuser
            orig_staff = request.user.is_staff
            if (action == 'password'):
                form = PasswordChangeForm(data=request.POST, user = request.user)
            elif (action == 'settings'):
                form = UserSettingsForm(request.POST, instance = request.user)
            if form.is_valid():
                ruser = form.save(commit = False)
                if not orig_superuser:
                    ruser.is_superuser = False
                    ruser.is_staff = orig_staff
                ruser.save()
                form.save_m2m()
                if action == 'settings':
                    try:
                        sciriususer = ruser.sciriususer
                        sciriususer.timezone = form.cleaned_data['timezone']
                    except:
                        sciriususer = SciriusUser.objects.create(user = ruser, timezone = form.cleaned_data['timezone'])
                    sciriususer.save()
            else:
                context['error'] = 'Invalid form'
            return scirius_render(request, 'accounts/edit.html', context)
        else:
            if (action == 'password'):
                form = PasswordChangeForm(request.user)
                context = { 'form': form, 'action': 'Change password' }
            elif (action == 'settings'):
                if request.user.is_superuser:
                    form = UserSettingsForm(instance = request.user, )
                else:
                    form = NormalUserSettingsForm(instance = request.user)
                try:
                    form.initial['timezone'] = request.user.sciriususer.timezone
                except:
                    pass
                context = { 'form': form, 'action': 'Edit settings for ' + request.user.username }
            else:
                context = { 'action': 'User settings' }
            return scirius_render(request, 'accounts/edit.html', context)

def manageview(request, action):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            if request.user.is_superuser:
                form.save()
            else:
                context['error'] = 'Not enough permission to create users'
        else:
            context['error'] = 'Invalid form'
    else:
        if (action == 'add'):
            form = UserCreationForm()
            context = { 'form': form, 'current_action': 'Add user'}
            return scirius_render(request, 'accounts/user.html', context)
    return scirius_listing(request, User, 'Users', adduri="/accounts/manage/add")

def manageuser(request, user_id):
    user = get_object_or_404(User, pk=user_id)
    context = { 'action': 'User actions', 'user': user }
    return scirius_render(request, 'accounts/user.html', context)

def manageuseraction(request, user_id, action):
    user = get_object_or_404(User, pk=user_id)
    context = { 'action': 'User actions', 'user': user }
    if request.method == 'POST':
        if not request.user.is_superuser:
            context['error'] = 'Unsufficient permissions'
            return scirius_render(request, 'accounts/user.html', context)
        if action == "edit":
            form = UserSettingsForm(request.POST, instance = user)
            if form.is_valid():
                form.save()
            else:
                context['error'] = 'Invalid form'
        return scirius_render(request, 'accounts/user.html', context)
    if action == "activate":
        if not request.user.is_superuser:
            context['error'] = 'Unsufficient permissions'
            return scirius_render(request, 'accounts/user.html', context)
        user.is_active = True
        user.save()
    elif action == "deactivate":
        if not request.user.is_superuser:
            context['error'] = 'Unsufficient permissions'
            return scirius_render(request, 'accounts/user.html', context)
        user.is_active = False
        user.save()
    elif action == "edit":
        if not request.user.is_superuser:
            context['error'] = 'Unsufficient permissions'
            return scirius_render(request, 'accounts/user.html', context)
        form = UserSettingsForm(instance = user)
        context = {'form': form }
        return scirius_render(request, 'accounts/user.html', context)
    elif action == "delete":
        if not request.user.is_superuser:
            context['error'] = 'Unsufficient permissions'
            return scirius_render(request, 'accounts/user.html', context)
        if request.GET.__contains__('confirm'):
            user.delete()
            return redirect('/accounts/manage/')
        else:
            context = { 'confirm_action': 'Delete user', 'user': user, 'action': 'delete'}
            return scirius_render(request, 'accounts/user.html', context)
    context = { 'action': 'User actions', 'user': user }
    return scirius_render(request, 'accounts/user.html', context)

def logoutview(request):
    logout(request)
    return redirect(settings.LOGIN_URL)



