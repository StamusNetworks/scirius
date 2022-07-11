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

import json

from django.shortcuts import redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.conf import settings
from django.contrib.auth.models import User, Group as DjangoGroup
from django.contrib.auth.decorators import permission_required
from rest_framework.authtoken.models import Token
from django.db.models import F
from django.http import JsonResponse, HttpResponseNotAllowed, HttpResponse

import django_tables2 as tables

from rules.models import UserAction
from rules.forms import CommentForm

from scirius.utils import scirius_render, scirius_listing, get_middleware_module
from .forms import LoginForm, UserSettingsForm, NormalUserSettingsForm, PasswordForm, TokenForm, PasswordChangeForm, GroupEditForm, PasswordCreationForm
from .models import SciriusUser, Group
from .tables import UserTable, GroupTable

from ipware.ip import get_client_ip
import logging


def loginview(request, target):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if not form.is_valid():  # All validation rules pass
            form = LoginForm()
            context = {'form': form, 'error': 'Invalid form'}
            return scirius_render(request, 'accounts/login.html', context)

        username = form.cleaned_data['username']
        password = form.cleaned_data['password']
        user = authenticate(username=username, password=password)
        if user is not None:
            if user.is_active:
                login(request, user)
                try:
                    sciriususer = SciriusUser.objects.get(user=user)
                    sciriususer.sciriususerapp
                except (SciriusUser.DoesNotExist, AttributeError):
                    SciriusUser.objects.get_or_create(user=user, defaults={'timezone': 'UTC'})
                    get_middleware_module('common').update_scirius_user_class(user, form.cleaned_data)

                if not form.cleaned_data['persistent']:
                    request.session.set_expiry(0)

                logger = logging.getLogger('authentication')
                logger.info("Successful login for '%s' from '%s'", username, get_client_ip(request))
                UserAction.create(
                    action_type='login',
                    request=request,
                    force_insert=True
                )
                if target:
                    return redirect("/" + target)
                return redirect(get_middleware_module('common').login_redirection_url(request))
            else:
                form = LoginForm()
                context = {'form': form, 'error': 'Disabled account'}
                logger = logging.getLogger('authentication')
                logger.error("Invalid login attempt for disabled account '%s' from '%s'", username, get_client_ip(request))
                return scirius_render(request, 'accounts/login.html', context)
        else:
            form = LoginForm()
            context = {'form': form, 'error': 'Invalid login'}
            logger = logging.getLogger('authentication')
            logger.error("Invalid login attempt for '%s' from '%s'", username, get_client_ip(request))
            return scirius_render(request, 'accounts/login.html', context)
    else:
        form = LoginForm()
        context = {'form': form}
        return scirius_render(request, 'accounts/login.html', context)


def editview(request, action):
    if request.user.is_authenticated:
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

            if request.user.has_perm('rules.configuration_auth'):
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
            context = {
                'action': 'User settings',
                'edition': False,
            }
            if get_middleware_module('common').has_multitenant():
                context['tenants'] = request.user.sciriususer.get_tenants()
                context['all_tenants'] = request.user.sciriususer.has_all_tenants()
                context['no_tenant'] = request.user.sciriususer.has_no_tenant()

        if request.method == 'POST':
            if form.is_valid():
                if action == 'token':
                    current_tokens = Token.objects.filter(user=request.user)
                    for token in current_tokens:
                        token.delete()
                    Token.objects.create(user=request.user)

                    UserAction.create(
                        action_type='edit_user_token',
                        comment=form.cleaned_data['comment'],
                        request=request,
                        other_user=request.user
                    )
                    return redirect('accounts_edit', action='token')

                context['edition'] = False
                context['action'] = 'User settings'

                ruser = form.save()
                if action == 'password':
                    update_session_auth_hash(request, ruser)

                    UserAction.create(
                        action_type='edit_user_password',
                        comment=form.cleaned_data['comment'],
                        request=request,
                        other_user=request.user
                    )
                if action == 'settings':
                    try:
                        sciriususer = ruser.sciriususer
                        sciriususer.timezone = form.cleaned_data['timezone']
                    except:
                        sciriususer = SciriusUser.objects.create(
                            user=ruser,
                            timezone=form.cleaned_data['timezone']
                        )
                        get_middleware_module('common').update_scirius_user_class(ruser, form.cleaned_data)

                    UserAction.create(
                        action_type='edit_user',
                        comment=form.cleaned_data['comment'],
                        request=request,
                        other_user=request.user
                    )
                    sciriususer.save()

        context.update({'is_from_ldap': request.user.sciriususer.is_from_ldap()})
        return scirius_render(request, 'accounts/edit.html', context)


@permission_required('rules.configuration_auth', raise_exception=True)
def list_accounts(request):
    template = 'accounts/accounts_list.html'
    mapping = {'User': UserTable, 'Role': GroupTable}
    klasses = (User, DjangoGroup)

    data = {
        'User': {
            'size': 0,
            'content': None,
            'annotate': {'role': F('groups__name')},
            'order_by': ('groups__group__priority', '-username')
        },
        'Role': {
            'size': 0,
            'content': None,
            'order_by': ('group__priority',)
        }
    }

    conf = tables.RequestConfig(request)
    for klass in klasses:
        klass_name = klass.__name__ if klass != DjangoGroup else 'Role'
        objects = klass.objects.all()
        if 'annotate' in data[klass_name]:
            objects = objects.annotate(**data[klass_name]['annotate'])

        objects = objects.order_by(*data[klass_name]['order_by'])
        data[klass_name]['content'] = conf.configure(mapping[klass_name](objects))
        data[klass_name]['size'] = objects.count()

    context = {'objects': data, 'extra_auth': get_middleware_module('common').has_extra_auth()}
    return scirius_render(request, template, context)


@permission_required('rules.configuration_auth', raise_exception=True)
def edit_priorities(request):
    groups = Group.objects.order_by('priority')
    return scirius_render(request, 'accounts/priorities.html', {'groups': groups})


@permission_required('rules.configuration_auth', raise_exception=True)
def sort_priorities(request):
    if request.method != 'POST' or not request.is_ajax():
        return HttpResponseNotAllowed('Only POST here')

    updated = False
    nb_static_groups = 3
    for index, group_pk in enumerate(request.POST.getlist('group[]'), start=nb_static_groups):
        group = get_object_or_404(DjangoGroup, pk=int(group_pk))
        Group.objects.filter(group=group).update(priority=index)
        if updated is False:
            updated = True
    return JsonResponse({'updated': updated})


@permission_required('rules.configuration_auth', raise_exception=True)
def list_users(request):
    assocfn = {
        'Users': {
            'table': UserTable,
            'annotate': {'role': F('groups__name')},
            'order_by': ('groups__group__priority', '-username'),
            'manage_links': {
                'list_accounts': 'Accounts list',
                'list_users': 'User list',
                'list_groups': 'Role list'
            },
            'action_links': {}
        }
    }
    return scirius_listing(request, User, assocfn, adduri="/accounts/user/add")


@permission_required('rules.configuration_auth', raise_exception=True)
def add_user(request):
    if request.method == 'POST':
        form = UserSettingsForm(request.POST)
        password_form = PasswordCreationForm(request.POST)

        if form.is_valid() and password_form.is_valid():
            ruser = form.save()
            ruser.set_password(password_form.cleaned_data['password1'])
            ruser.save()

            UserAction.create(
                action_type='create_user',
                comment=form.cleaned_data['comment'],
                request=request,
                new_user=ruser
            )

            return redirect('list_accounts')

        context = {
            'error': 'Username and/or password are not valid',
            'form': form,
            'password_form': password_form,
            'current_action': 'Add user'
        }
        return scirius_render(request, 'accounts/user.html', context)

    form = UserSettingsForm()
    password_form = PasswordCreationForm()
    context = {'form': form, 'current_action': 'Add user', 'password_form': password_form}
    return scirius_render(request, 'accounts/user.html', context)


@permission_required('rules.configuration_auth', raise_exception=True)
def edit_user(request, user_id):
    user = get_object_or_404(User, pk=user_id)
    context = {
        'user': user,
        'username': json.dumps(user.username),
        'current_action': f"Edit{' LDAP ' if user.sciriususer.is_from_ldap() else ' '}user {user.username}",
        'is_from_ldap': user.sciriususer.is_from_ldap()
    }

    if request.method == 'POST':
        form = UserSettingsForm(request.POST, instance=user)
        if form.is_valid():
            user = form.save()

            UserAction.create(
                action_type='edit_user',
                comment=form.cleaned_data['comment'],
                request=request,
                other_user=user
            )
            return redirect('list_accounts')

        context['error'] = 'Edition form is not valid'
        context['form'] = form
        return scirius_render(request, 'accounts/user.html', context)

    form = UserSettingsForm(instance=user)
    context['form'] = form
    return scirius_render(request, 'accounts/user.html', context)


@permission_required('rules.configuration_auth', raise_exception=True)
def delete_user(request, user_id):
    if request.method != 'POST':
        return HttpResponseNotAllowed('Only POST here')

    user = get_object_or_404(User, pk=user_id)
    comment_form = CommentForm(request.POST)

    if not comment_form.is_valid():
        return JsonResponse({'error': '\n'.join(comment_form.errors)})

    user.delete()
    UserAction.create(
        action_type='delete_user',
        comment=comment_form.cleaned_data['comment'],
        request=request,
        old_user=user
    )
    return JsonResponse({'redirect': '/accounts/user/'})


@permission_required('rules.configuration_auth', raise_exception=True)
def list_groups(request):
    assocfn = {
        'Roles': {
            'table': GroupTable,
            'order_by': ('group__priority',),
            'manage_links': {
                'list_accounts': 'Accounts list',
                'list_users': 'User list',
                'list_groups': 'Role list'
            },
            'action_links': {}
        }
    }
    return scirius_listing(request, DjangoGroup, assocfn, adduri="/accounts/role/add")


@permission_required('rules.configuration_auth', raise_exception=True)
def add_group(request):
    if request.method == 'POST':
        form = GroupEditForm(request.POST)
        if form.is_valid():
            group = form.save()

            UserAction.create(
                action_type='create_group',
                comment=form.cleaned_data['comment'],
                request=request,
                new_group=group
            )

            return redirect('list_accounts')

        context = {
            'form': form,
            'current_action': 'Add role',
            'can_edit': True
        }
        return scirius_render(request, 'accounts/group.html', context)

    form = GroupEditForm()
    context = {
        'form': form,
        'current_action': 'Add role',
        'mapping': json.dumps(form.mapping),
        'can_edit': True
    }
    return scirius_render(request, 'accounts/group.html', context)


@permission_required('rules.configuration_auth', raise_exception=True)
def edit_group(request, group_id):
    django_group = get_object_or_404(DjangoGroup, pk=group_id)
    context = {'group': django_group, 'action': 'edit', 'group_name': json.dumps(django_group.name)}

    if request.method == 'POST':
        form = GroupEditForm(request.POST, instance=django_group)
        if form.is_valid():
            form.save()

            UserAction.create(
                action_type='edit_group',
                comment=form.cleaned_data['comment'],
                request=request,
                group=django_group
            )
            return redirect('list_accounts')

        context['error'] = 'Edition form is not valid'
        context['form'] = form
        context['current_action'] = 'Edit group %s' % django_group.name
        return scirius_render(request, 'accounts/group.html', context)

    form = GroupEditForm(instance=django_group)
    context['can_edit'] = django_group.name not in GroupEditForm.DEFAULT_GROUPS
    context['form'] = form
    context['mapping'] = json.dumps(form.mapping)
    context['current_action'] = 'Edit role %s' % django_group.name
    return scirius_render(request, 'accounts/group.html', context)


@permission_required('rules.configuration_auth', raise_exception=True)
def delete_group(request, group_id):
    if request.method != 'POST':
        return HttpResponseNotAllowed('Only POST here')

    group = get_object_or_404(DjangoGroup, pk=group_id)
    comment_form = CommentForm(request.POST)

    if not comment_form.is_valid():
        return JsonResponse({'error': '\n'.join(comment_form.errors)})

    Group.objects.filter(
        priority__gt=group.group.priority,
    ).update(priority=F('priority') - 1)

    group.delete()
    UserAction.create(
        action_type='delete_group',
        comment=comment_form.cleaned_data['comment'],
        request=request,
        group=group.group
    )
    return JsonResponse({'redirect': '/accounts/role/'})


@permission_required('rules.configuration_auth', raise_exception=True)
def edit_password(request, user_id):
    user = get_object_or_404(User, pk=user_id)
    context = {'user': user, 'username': json.dumps(user.username)}

    if request.method == 'POST':
        form = PasswordForm(request.POST)
        if form.is_valid():
            user.set_password(form.cleaned_data['password'])
            user.save()
            if user == request.user:
                # If the user change his own password prevent the session to be invalidated
                update_session_auth_hash(request, user)

            UserAction.create(
                action_type='edit_user_password',
                comment=form.cleaned_data['comment'],
                request=request,
                other_user=user
            )
            return redirect('list_accounts')
        else:
            context['error'] = 'Password form is not valid'
            context['form'] = form

        return scirius_render(request, 'accounts/user.html', context)

    form = PasswordForm()
    context['form'] = form
    context['current_action'] = 'Edit password for user %s' % user.username
    return scirius_render(request, 'accounts/user.html', context)


def logoutview(request):
    from rules.models import UserAction
    UserAction.create(
        action_type='logout',
        request=request,
        force_insert=True
    )
    logout(request)
    return redirect(settings.LOGIN_URL)


def current_user(request):
    return HttpResponse(
        'var current_user = %s' % json.dumps(request.user.sciriususer.to_dict(json_compatible=True)),
        content_type='application/x-javascript'
    )
