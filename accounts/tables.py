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

from collections import OrderedDict
from django.contrib.auth.models import User, Permission, Group as DjangoGroup
from django.urls import reverse
from django.utils.html import format_html
from scirius.utils import SciriusTable
import django_tables2 as tables
from scirius.utils import get_middleware_module
from accounts.models import SciriusUser


class DefaultMeta:
    attrs = {"class": "paleblue"}


class TokenListTable(SciriusTable):
    username = tables.Column(verbose_name='Token name')
    token = tables.Column(empty_values=(), verbose_name='Token')
    role = tables.Column(empty_values=())
    description = tables.Column(empty_values=())

    class Meta(DefaultMeta):
        model = User
        fields = ('username', 'role', 'token', 'description', 'active')
        exclude = []

    def render_username(self, record):
        if self.is_owner:
            return format_html(
                '<a href="{}">{}</a>',
                reverse('token_edit', args=[record['pk']]),
                record['username']
            )
        return record['username']

    def __init__(self, data, *args, **kwargs):
        rows = {}
        extra_columns = {}
        add_parent = kwargs.pop('add_parent', False)
        self.is_owner = kwargs.pop('is_owner', False)

        for row in data:
            if row.pk not in rows:
                user = row.user
                sciriususer = user.sciriususer
                sciriustokenuser = sciriususer.sciriustokenuser

                rows[user.pk] = {
                    'username': user.username,
                    'token': user.auth_token.key,
                    'role': user.groups.first().name,
                    'description': sciriustokenuser.description,
                    'pk': row.user.pk,
                    'tenants': ''
                }

                rows[user.pk]['active'] = '✔' if user.is_active else '✘'  # ignore_utf8_check: 10008 10004

                if add_parent:
                    extra_columns['parent'] = tables.Column(
                        verbose_name='Parent',
                        attrs={'td': {'style': 'white-space:pre-wrap;'}}
                    )
                    extra_columns['parent_active'] = tables.Column(
                        verbose_name='Parent Active',
                        attrs={'td': {'style': 'white-space:pre-wrap;'}}
                    )
                    rows[user.pk]['parent'] = sciriustokenuser.parent.user.username
                    rows[user.pk]['parent_active'] = '✔' if sciriustokenuser.parent.user.is_active else '✘'  # ignore_utf8_check: 10008 10004
                else:
                    extra_columns['permissions'] = tables.TemplateColumn('{{ record.permissions|linebreaksbr }}')
                    rows[user.pk]['permissions'] = '\n'.join(list(user.groups.first().permissions.values_list('name', flat=True)))

                if get_middleware_module('common').has_multitenant():
                    rows[user.pk]['tenants'] = ''
                    if sciriususer.has_no_tenant():
                        rows[user.pk]['tenants'] = 'No tenant\n'

                    if sciriususer.has_all_tenants():
                        rows[user.pk]['tenants'] += 'All tenants'
                    else:
                        rows[user.pk]['tenants'] += '\n'.join(sciriususer.get_tenants().values_list('name', flat=True))
                    extra_columns['tenants'] = tables.Column(verbose_name='Tenants', attrs={'td': {'style': 'white-space:pre-wrap;'}})

        super().__init__(data=rows.values(), extra_columns=extra_columns.items(), *args, **kwargs)


class UserTable(SciriusTable):
    username = tables.LinkColumn('edit_user', args=[tables.A('pk')])
    role = tables.Column()

    class Meta(DefaultMeta):
        model = User
        fields = ("username", "first_name", "last_name", "email", "role", "active")

    def render_role(self, record):
        return format_html('<a href="{}">{}</a>', reverse('edit_group', args=[record['role'].pk]), record['role'].name)

    def __init__(self, data, *args, **kwargs):
        rows = OrderedDict()
        extra_columns = {}

        for row in data:
            if row.pk not in rows:
                rows[row.pk] = {
                    'username': row.username,
                    'first_name': row.first_name,
                    'last_name': row.last_name,
                    'email': row.email,
                    'role': row.groups.first(),
                    'pk': row.pk
                }

                # because of AD inactive users, that create User but not SciriusUser
                try:
                    SciriusUser.objects.get(user=row)
                except SciriusUser.DoesNotExist:
                    SciriusUser.objects.create(user=row, timezone='UTC')
                    get_middleware_module('common').update_scirius_user_class(row, {})

                rows[row.pk]['active'] = '✔' if row.is_active else '✘'  # ignore_utf8_check: 10008 10004

                if get_middleware_module('common').has_multitenant():
                    rows[row.pk]['tenants'] = ''
                    if row.sciriususer.has_no_tenant():
                        rows[row.pk]['tenants'] = 'No tenant\n'

                    if row.sciriususer.has_all_tenants():
                        rows[row.pk]['tenants'] += 'All tenants'
                    else:
                        rows[row.pk]['tenants'] += '\n'.join(row.sciriususer.get_tenants().values_list('name', flat=True))
                    extra_columns['tenants'] = tables.Column(verbose_name='Tenants', attrs={'td': {'style': 'white-space:pre-wrap;'}})

                if get_middleware_module('common').has_ldap_auth() or get_middleware_module('common').has_saml_auth():
                    rows[row.pk]['method'] = get_middleware_module('common').auth_choices().get(row.sciriususer.method())
                    extra_columns['method'] = tables.Column(verbose_name='Authentification')

        super().__init__(data=rows.values(), extra_columns=extra_columns.items(), *args, **kwargs)


class GroupTable(SciriusTable):
    name = tables.Column()

    class Meta(DefaultMeta):
        model = DjangoGroup
        fields = ('name',)

    def render_name(self, record):
        if self.token_role:
            return record['name']

        return format_html(
            '<a href="{}">{}</a>',
            reverse('edit_group', args=[record['pk']]),
            record['name']
        )

    def __init__(self, data, *args, **kwargs):
        rows = OrderedDict()
        extra_columns = {}
        self.token_role = kwargs.pop('token_role', False)

        # Superuser group has all custom permissions
        # => Usefull to get our custom permissions
        permissions = Permission.objects.filter(group__name='Superuser')

        for row in data:
            if row.pk not in rows:
                rows[row.pk] = {
                    'name': row.name,
                    'pk': row.pk
                }

                if get_middleware_module('common').has_ldap_auth():
                    rows[row.pk]['priority'] = str(row.group.priority)
                    extra_columns['priority'] = tables.Column(verbose_name='Priority')

                    rows[row.pk]['ldap_group'] = row.group.ldap_group
                    extra_columns['ldap_group'] = tables.Column(verbose_name='LDAP Group')

                for permission in permissions:
                    if row.permissions.filter(pk=permission.pk).count() > 0:
                        rows[row.pk][permission.codename] = '✔'  # ignore_utf8_check: 10008 10004
                    else:
                        rows[row.pk][permission.codename] = '✘'  # ignore_utf8_check: 10008 10004

                    extra_columns[permission.codename] = tables.Column(verbose_name=permission.name)

        super().__init__(data=rows.values(), extra_columns=extra_columns.items(), *args, **kwargs)
