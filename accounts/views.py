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
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm, UserCreationForm
from django.conf import settings
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token

from scirius.utils import scirius_render, scirius_listing
from forms import LoginForm, UserSettingsForm, NormalUserSettingsForm, PasswordForm, DeleteForm, TokenForm
from models import SciriusUser

from ipware.ip import get_real_ip
import logging

def loginview(request, target):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if not form.is_valid(): # All validation rules pass
            form = LoginForm()
            context = { 'form': form, 'error': 'Invalid form' }
            return scirius_render(request, 'accounts/login.html', context)
        username = form.cleaned_data['username']
        password = form.cleaned_data['password']
        user = authenticate(username=username, password=password)
        if user is not None:
            if user.is_active:
                login(request, user)
                if not form.cleaned_data['persistent']:
                    request.session.set_expiry(0)
                logger = logging.getLogger('authentication')
                logger.info("Successful login for '%s' from '%s'", username, get_real_ip(request))
                from rules.models import UserAction
                UserAction.create(
                        action_type='login',
                        user=user,
                        force_insert=True
                )
                return redirect("/" + target)
            else:
                form = LoginForm()
                context = { 'form': form, 'error': 'Disabled account' }
                logger = logging.getLogger('authentication')
                logger.error("Invalid login attempt for disabled account '%s' from '%s'", username, get_real_ip(request))
                return scirius_render(request, 'accounts/login.html', context)
        else:
            form = LoginForm()
            context = { 'form': form, 'error': 'Invalid login' }
            logger = logging.getLogger('authentication')
            logger.error("Invalid login attempt for '%s' from '%s'", username, get_real_ip(request))
            return scirius_render(request, 'accounts/login.html', context)
    else:
        form = LoginForm()
        context = { 'form': form }
        return scirius_render(request, 'accounts/login.html', context)


def editview(request, action):
    if request.user.is_authenticated():
        request_data = None
        context = {}

        if request.method == 'POST':
            request_data = request.POST

        if action == 'password':
            form = PasswordChangeForm(user=request.user, data=request_data)
            context = {'form': form, 'action': 'Change password', 'edition': True}
        elif action == 'settings':
            tz = 'UTC'
            if hasattr(request.user, 'sciriususer'):
                tz = request.user.sciriususer.timezone
            initial = {'timezone': tz}

            if request.user.is_superuser:
                form = UserSettingsForm(request_data, instance=request.user, initial=initial)
            else:
                form = NormalUserSettingsForm(request_data, instance=request.user, initial=initial)

            context = {'form': form, 'action': 'Edit settings for ' + request.user.username, 'edition': True}
        elif action == 'token':
            initial = {}
            token = Token.objects.filter(user=request.user)
            if len(token):
                initial['token'] = token[0]
            form = TokenForm(request_data, initial=initial)
            context = {'form': form, 'action': 'User token', 'edition': True}
        else:
            context = {'action': 'User settings', 'edition': False}

        if request.method == 'POST':
            if action == 'token':
                current_tokens = Token.objects.filter(user=request.user)
                for token in current_tokens:
                    token.delete()
                Token.objects.create(user=request.user)
                return redirect('accounts_edit', action='token')

            orig_superuser = request.user.is_superuser
            orig_staff = request.user.is_staff
            if form.is_valid():
                context['edition'] = False
                context['action'] = 'User settings'

                ruser = form.save(commit = False)
                if not orig_superuser:
                    ruser.is_superuser = False
                    ruser.is_staff = orig_staff
                ruser.save()
                if action == 'password':
                    update_session_auth_hash(request, ruser)
                if action == 'settings':
                    try:
                        sciriususer = ruser.sciriususer
                        sciriususer.timezone = form.cleaned_data['timezone']
                    except:
                        sciriususer = SciriusUser.objects.create(user = ruser, timezone = form.cleaned_data['timezone'])
                    sciriususer.save()
        return scirius_render(request, 'accounts/edit.html', context)


def manageview(request, action):
    context = { 'action': 'User management' }
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            if request.user.is_superuser:
                ruser = form.save()

                sciriususer = SciriusUser.objects.create(user=ruser, timezone='UTC')
                sciriususer.save()
            else:
                context['error'] = 'Not enough permission to create users'
        else:
            if action != 'add':
                context['error'] = 'Invalid form'
            else:
                context['error'] = 'Username and/or password are not valid'

            context['form'] = form
            return scirius_render(request, 'accounts/user.html', context)
    else:
        if request.user.is_superuser is False:
            if len(action) == 0:
                action = 'list'

            context['error'] = 'Not enough permission to %s users' % action
            return scirius_render(request, 'accounts/user.html', context)

        if (action == 'add'):
            form = UserCreationForm()
            context = { 'form': form, 'current_action': 'Add user'}
            return scirius_render(request, 'accounts/user.html', context)

    return scirius_listing(request, User, 'Users', adduri="/accounts/manage/add")

def manageuser(request, user_id):
    user = get_object_or_404(User, pk=user_id)
    context = {'action': 'User actions', 'user': user}
    if not request.user.is_superuser:
        context['error'] = 'Unsufficient permissions'
        context['user'] = get_object_or_404(User, pk=request.user.pk)
    return scirius_render(request, 'accounts/user.html', context)

def manageuseraction(request, user_id, action):
    user = get_object_or_404(User, pk=user_id)
    context = {'action': 'User actions', 'user': user}
    if request.method == 'POST':
        if not request.user.is_superuser:
            context['error'] = 'Unsufficient permissions'
            return scirius_render(request, 'accounts/user.html', context)
        if action == "edit":
            form = UserSettingsForm(request.POST, instance = user)
            if form.is_valid():
                form.save()
                try:
                    sciriususer = user.sciriususer
                    sciriususer.timezone = form.cleaned_data['timezone']
                except:
                    sciriususer = SciriusUser.objects.create(user = user, timezone = form.cleaned_data['timezone'])
                sciriususer.save()
            else:
                context['error'] = 'Edition form is not valid'
                context['form'] = form
        elif action == 'password':
            form = PasswordForm(request.POST)
            if form.is_valid():
                user.set_password(form.cleaned_data['password'])
                user.save()
                if user == request.user:
                    # If the user change his own password prevent the session to be invalidated
                    update_session_auth_hash(request, user)
            else:
                context['error'] = 'Password form is not valid'
        elif action == "delete":
            form = DeleteForm(request.POST)
            if form.is_valid():
                if request.POST.__contains__('confirm'):
                    user.delete()
                    return redirect('/accounts/manage/')
            else:
                context['error'] = 'Delete form is not valid'

        return scirius_render(request, 'accounts/user.html', context)

    if not request.user.is_superuser:
        context['error'] = 'Unsufficient permissions'
        context['user'] = get_object_or_404(User, pk=request.user.pk)
        return scirius_render(request, 'accounts/user.html', context)

    if action == "activate":
        user.is_active = True
        user.save()
        context['current_action'] = 'Activate user %s' % user.username
    elif action == "deactivate":
        user.is_active = False
        user.save()
        context['current_action'] = 'Deactivate user %s' % user.username
    elif action == "edit":
        form = UserSettingsForm(instance = user)
        try:
            form.initial['timezone'] = user.sciriususer.timezone
        except:
            pass
        context['form'] = form
        context['current_action'] = 'Edit user %s' % user.username
        return scirius_render(request, 'accounts/user.html', context)
    elif action == "password":
        form = PasswordForm()
        context['form'] = form
        context['current_action'] = 'Edit password for user %s' % user.username
        return scirius_render(request, 'accounts/user.html', context)
    elif action == "delete":
        context = { 'confirm_action': 'Delete user', 'user': user, 'action': 'delete'}
        return scirius_render(request, 'accounts/user.html', context)

    context['current_action'] = 'User %s' % user.username
    return scirius_render(request, 'accounts/user.html', context)


def logoutview(request):
    from rules.models import UserAction
    UserAction.create(
            action_type='logout',
            user=request.user,
            force_insert=True
    )
    logout(request)
    return redirect(settings.LOGIN_URL)
