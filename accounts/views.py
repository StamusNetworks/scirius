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

from django.shortcuts import redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.forms import PasswordChangeForm
from django.conf import settings

from scirius.utils import scirius_render
from forms import LoginForm, UserSettingsForm

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
            if (action == 'password'):
                form = PasswordChangeForm(data=request.POST, user=request.user)
            elif (action == 'settings'):
                form = UserSettingsForm(request.POST, instance = request.user)
            if form.is_valid():
                form.save()
            else:
                context['error'] = 'Invalid form'
            return scirius_render(request, 'accounts/edit.html', context)
        else:
            if (action == 'password'):
                form = PasswordChangeForm(request.user)
                context = { 'form': form, 'action': 'Change password' }
            elif (action == 'settings'):
                form = UserSettingsForm(instance = request.user)
                context = { 'form': form, 'action': 'Edit settings for ' + request.user.username }
            else:
                context = { 'action': 'User settings' }
            return scirius_render(request, 'accounts/edit.html', context)


def logoutview(request):
    logout(request)
    return redirect(settings.LOGIN_URL)



