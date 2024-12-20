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
from django.core.exceptions import PermissionDenied

from django.shortcuts import redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.conf import settings
from django.contrib.auth.models import User, Group as DjangoGroup
from django.contrib.auth.decorators import permission_required
from django.views.decorators.cache import never_cache
from rest_framework.authtoken.models import Token
from django.db.models import F
from django.http import JsonResponse, HttpResponseNotAllowed, HttpResponse
from django.utils import timezone

import django_tables2 as tables
from django.db import transaction

from rules.models import UserAction, get_system_settings
from rules.forms import CommentForm

from scirius.utils import scirius_render, scirius_listing, get_middleware_module, is_ajax
from .forms import (
    LoginForm, TokenGroupForm, TokenUserForm, UserSettingsForm, NormalUserSettingsForm,
    PasswordForm, TokenForm, PasswordChangeForm, GroupEditForm, PasswordCreationForm
)
from .models import SciriusTokenUser, SciriusUser, Group
from .tables import TokenListTable, UserTable, GroupTable

from ipware.ip import get_client_ip
import logging


@never_cache
def loginview(request, target):
    banner = get_system_settings().custom_login_banner
    context = {'logo': settings.LOGO}

    if request.method == 'POST':
        form = LoginForm(request.POST)
        if not form.is_valid():  # All validation rules pass
            form = LoginForm()
            context.update({'form': form, 'error_login': 'Invalid form', 'banner': banner})
            return scirius_render(request, 'accounts/login.html', context)

        username = form.cleaned_data['username']
        password = form.cleaned_data['password']
        user = authenticate(username=username, password=password)
        if user is not None:
            if user.is_active:
                login(request, user)
                request.session['session_start'] = timezone.now()
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
                session_activity(request)
                if target:
                    return redirect("/" + target)
                return redirect(get_middleware_module('common').login_redirection_url(request))
            else:
                form = LoginForm()
                context.update({'form': form, 'error_login': 'Disabled account', 'banner': banner})
                logger = logging.getLogger('authentication')
                logger.error("Invalid login attempt for disabled account '%s' from '%s'", username, get_client_ip(request))
                return scirius_render(request, 'accounts/login.html', context)
        else:
            form = LoginForm()
            context.update({'form': form, 'error_login': 'Invalid login', 'banner': banner})
            logger = logging.getLogger('authentication')
            logger.error("Invalid login attempt for '%s' from '%s'", username, get_client_ip(request))
            return scirius_render(request, 'accounts/login.html', context)
    else:
        form = LoginForm()
        context.update({'form': form, 'banner': banner, 'saml': get_middleware_module('common').has_saml_auth()})
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
            if token.count():
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
    data = {
        'User': {
            'size': 0,
            'content': None,
            'annotate': {'role': F('groups__name')},
            'filter': {'sciriususer__sciriustokenuser__parent__isnull': True},
            'order_by': ('groups__group__priority', '-username'),
            'class': User,
            'table': UserTable
        },
        'Role': {
            'size': 0,
            'content': None,
            'order_by': ('group__priority',),
            'filter': {'user__sciriususer__sciriustokenuser__parent__isnull': True},
            'class': DjangoGroup,
            'table': GroupTable
        },
        'Token User': {
            'size': 0,
            'content': None,
            'filter': {'sciriustokenuser__parent__isnull': False},
            'order_by': ('-sciriustokenuser__parent__user__username',),
            'table_params': {'add_parent': True, 'exclude': ('token',)},
            'class': SciriusUser,
            'table': TokenListTable
        },
        'Token Role': {
            'size': 0,
            'content': None,
            'filter': {'user__sciriususer__sciriustokenuser__parent__isnull': False},
            'order_by': ('-user__sciriususer__sciriustokenuser__parent__user__username',),
            'table_params': {'token_role': True},
            'class': DjangoGroup,
            'table': GroupTable
        }
    }

    conf = tables.RequestConfig(request)

    for _, values in data.items():
        objects = values.pop('class').objects.all()

        for item in ('annotate', 'filter'):
            if item in values.keys():
                objects = getattr(objects, item)(**values.pop(item))

        objects = objects.order_by(*values.pop('order_by'))

        table_params = {'data': objects}
        if 'table_params' in values:
            table_params.update(values.pop('table_params'))

        values['content'] = conf.configure(values.pop('table')(**table_params))
        values['size'] = objects.distinct().count()

    context = {'objects': data, 'extra_auth': get_middleware_module('common').has_ldap_auth()}
    return scirius_render(request, 'accounts/accounts_list.html', context)


@permission_required('rules.configuration_auth', raise_exception=True)
def edit_priorities(request):
    groups = Group.objects.order_by('priority')
    return scirius_render(request, 'accounts/priorities.html', {'groups': groups})


@permission_required('rules.configuration_auth', raise_exception=True)
def sort_priorities(request):
    if request.method != 'POST' or not is_ajax(request):
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
        'User': {
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
    queryset = User.objects.filter(sciriususer__sciriustokenuser__parent__isnull=True)
    return scirius_listing(request, queryset, assocfn, adduri="/accounts/user/add")


def _build_group_and_user_token(request, context, user=None):
    group_form = TokenGroupForm(
        data=request.POST,
        req_user=request.user,
        instance=user.groups.first() if user and user.groups.exists() else None
    )
    user_form = TokenUserForm(data=request.POST, req_user=request.user, instance=user)

    if not group_form.is_valid() or not user_form.is_valid():
        errors = {}
        errors.update(group_form.errors)
        errors.update(user_form.errors)
        context.update({
            'group_form': group_form,
            'user_form': user_form,
            'error': f'Invalid form: {errors}'
        })
        return scirius_render(request, 'accounts/token_add.html', context)

    with transaction.atomic():
        group = group_form.save()
        user = user_form.save()
        user.groups.set([group])
        Token.objects.get_or_create(user=user)
    return redirect('token_list')


def token_delete(request, user_id):
    token_user = get_object_or_404(User, pk=user_id)
    with transaction.atomic():
        token_user.groups.first().delete()
        token_user.delete()
    return redirect('token_list')


def token_edit(request, user_id):
    user = get_object_or_404(User, pk=user_id)
    token_user = SciriusTokenUser.objects.filter(user=user).first()
    if not token_user or token_user.parent.user != request.user:
        raise PermissionDenied()

    context = {}
    if request.method == 'POST':
        return _build_group_and_user_token(request, context, user=user)

    context.update({
        'group_form': TokenGroupForm(req_user=request.user, instance=user.groups.first()),
        'user_form': TokenUserForm(req_user=request.user, instance=user),
        'instance': user
    })
    return scirius_render(request, 'accounts/token_add.html', context)


def token_list(request):
    sn_users = request.user.sciriususer.tokenusers.all()
    token_table = TokenListTable(sn_users, is_owner=True)
    tables.RequestConfig(request).configure(token_table)

    return scirius_render(request, 'accounts/token_list.html', {'token_table': token_table})


def token_add(request):
    context = {}
    if request.method == 'POST':
        return _build_group_and_user_token(request, context)

    context.update({
        'group_form': TokenGroupForm(req_user=request.user),
        'user_form': TokenUserForm(req_user=request.user)
    })
    return scirius_render(request, 'accounts/token_add.html', context)


@permission_required('rules.configuration_auth', raise_exception=True)
def add_user(request):
    if request.method == 'POST':
        form = UserSettingsForm(request.POST)
        password_form = PasswordCreationForm(request.POST)

        if form.is_valid() and password_form.is_valid():
            ruser = form.save()
            if form.cleaned_data.get('saml', False) is False:
                ruser.set_password(password_form.cleaned_data['password1'])
            else:
                ruser.set_unusable_password()

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

    method = 'Local'
    try:
        method = get_middleware_module('common').auth_choices().get(user.sciriususer.method())
    except AttributeError:
        pass

    context = {
        'user': user,
        'username': json.dumps(user.username),
        'current_action': f"Edit {method} user {user.username}",
        'is_from_ldap': user.sciriususer.is_from_ldap(),
        'show_perm_warning': user.sciriususer.has_kibana_or_evebox_perm()
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
        'Role': {
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
    queryset = DjangoGroup.objects.filter(user__sciriususer__sciriustokenuser__parent__isnull=True).distinct()
    return scirius_listing(request, queryset, assocfn, adduri="/accounts/role/add")


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
    scirius_user = request.user.sciriususer

    context = {
        'group': django_group,
        'action': 'edit',
        'group_name': json.dumps(django_group.name),
        'show_perm_warning': scirius_user.has_all_tenants() and scirius_user.has_no_tenant()
    }

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
        group=group
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
    js = get_middleware_module('common').current_user_js(request)
    return HttpResponse(js, content_type='application/x-javascript')


def session_activity(request):
    '''
    This is not accessible via URLs.
    This is used only on login view to set expiry
    '''
    timeout = int(request.POST.get('timeout', '0'))
    cookie_age = get_system_settings().custom_cookie_age
    disconnect = timeout >= cookie_age * 3600
    if disconnect:
        logout(request)
    else:
        expiry = cookie_age * 3600 - timeout
        request.session.set_expiry(expiry)
