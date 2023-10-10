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


from django.db import models
from django.contrib.auth.models import User, Group as DjangoGroup
import pytz
import django_auth_ldap.backend


def get_next_priority():
    return Group.objects.aggregate(models.Max('priority')).get('priority__max') + 1


class Group(models.Model):
    group = models.OneToOneField(DjangoGroup, on_delete=models.CASCADE)
    ldap_group = models.CharField(max_length=400, default='')
    priority = models.IntegerField(default=get_next_priority)

    @property
    def name(self):
        return self.group.name

    @property
    def permissions(self):
        return self.group.permissions


def update_groups(sender, user, ldap_user, **kwargs):
    '''
    Update LDAP group each time a LDAP user login into scirius
    '''
    from scirius.utils import get_middleware_module

    nb_items_max = 100
    filters = models.Q()
    group = None
    stop_idx = len(ldap_user.group_dns)

    for idx, ldap_group in enumerate(ldap_user.group_dns, 1):
        filters |= models.Q(ldap_group__iexact=ldap_group)

        if idx % nb_items_max == 0 or idx == stop_idx:
            found_group = Group.objects.filter(filters).order_by('priority').first()
            filters = models.Q()

            if found_group:
                if not group:
                    group = found_group

                if group.priority > found_group.priority:
                    group = found_group

    user.save()
    user.groups.clear()

    try:
        sciriususer = SciriusUser.objects.get(user=user)
        sciriususerapp = sciriususer.sciriususerapp
        if sciriususerapp.method not in ('ldap', 'saml'):
            sciriususerapp.method = 'ldap'
            sciriususerapp.save()
    except (SciriusUser.DoesNotExist, AttributeError):
        SciriusUser.objects.get_or_create(user=user, defaults={'timezone': 'UTC'})
        get_middleware_module('common').update_scirius_user_class(user, {'method': 'ldap'})

    if group is not None:
        user.groups.add(group.group)


django_auth_ldap.backend.populate_user.connect(update_groups)


class SciriusUser(models.Model):
    TIMEZONES = ((x, x) for x in pytz.all_timezones)
    FAKE_USER = {
        'pk': 1,
        'timezone': 'Europe/Paris',
        'username': 'scirius',
        'first_name': '',
        'last_name': '',
        'is_active': True,
        'email': 'admin@domain.com',
        'date_joined': '2014-11-05T16:06:38.113000Z',
        'perms': [
            'rules.events_ryod',
            'rules.events_evebox',
            'rules.events_kibana',
            'rules.events_edit',
            'rules.events_view',
            'rules.ruleset_update_push',
            'rules.ruleset_policy_edit',
            'rules.ruleset_policy_view',
            'rules.source_edit',
            'rules.source_view',
            'rules.configuration_auth',
            'rules.configuration_edit',
            'rules.configuration_view'
        ],
        'role': 'Superuser',
        'no_tenant': True,
        'all_tenant': True,
        'tenants': []
    }

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    timezone = models.CharField(max_length=40, choices=TIMEZONES)

    def to_dict(self, json_compatible=False):
        from scirius.utils import get_middleware_module

        tenants = []
        if self.has_all_tenants():
            tenants = get_middleware_module('common').get_tenants().values_list('pk', flat=True)
        else:
            tenants = self.get_tenants()
            if not isinstance(tenants, (list, tuple)):
                tenants = tenants.values_list('pk', flat=True)

        if json_compatible:
            tenants = list(tenants)

        res = {
            "pk": self.pk,
            "timezone": self.timezone,
            "username": self.user.username,
            "first_name": self.user.first_name,
            "last_name": self.user.last_name,
            "is_active": self.user.is_active,
            "email": self.user.email,
            "date_joined": self.user.date_joined if not json_compatible else self.user.date_joined.isoformat(),
            "perms": ['rules.{}'.format(item[0]) for item in self.user.groups.values_list('permissions__codename')],
            "role": self.user.groups.first().name,
            "no_tenant": self.has_no_tenant(),
            "all_tenant": self.has_all_tenants(),
            "tenants": tenants,
            "method": self.method()
        }

        if get_middleware_module('common').has_ldap_auth():
            res.update({
                'group': Group.objects.filter(group__user=self.user).first().ldap_group
            })

        return res

    def get_tenants(self):
        if not hasattr(self, 'sciriususerapp'):
            from scirius.utils import get_middleware_module
            return get_middleware_module('common').get_tenants(empty_queryset=True)
        return self.sciriususerapp.tenants.all()

    def has_no_tenant(self):
        if not hasattr(self, 'sciriususerapp'):
            return False
        return self.sciriususerapp.no_tenant

    def has_all_tenants(self):
        if not hasattr(self, 'sciriususerapp'):
            return False
        return self.sciriususerapp.all_tenants

    @staticmethod
    def get_no_tenant_idx():
        from scirius.utils import get_middleware_module
        if get_middleware_module('common').has_multitenant():
            return 0
        return -1

    def is_from_ldap(self):
        if not hasattr(self, 'sciriususerapp'):
            return False
        return self.sciriususerapp.method == 'ldap'

    def is_from_saml(self):
        if not hasattr(self, 'sciriususerapp'):
            return False
        return self.sciriususerapp.method == 'saml'

    def method(self):
        if not hasattr(self, 'sciriususerapp'):
            return 'local'
        return self.sciriususerapp.method

    def set_method(self, method):
        if hasattr(self, 'sciriususerapp'):
            self.sciriususerapp.method = method
            self.sciriususerapp.save()
