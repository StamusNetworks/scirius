"""
Copyright(C) 2014-2018 Stamus Networks
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

import fcntl
from django.db import models
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey, GenericRelation
from django.conf import settings
from django.core.exceptions import FieldError, SuspiciousOperation, ValidationError
from django.core.validators import validate_ipv4_address
from django.db import transaction
from django.urls import reverse
from django.utils import timezone
from django.utils.html import format_html, format_html_join
from idstools import rule as rule_idstools
from enum import Enum, unique
from copy import deepcopy
from collections import OrderedDict
import tempfile
import tarfile
import re
import os
import git
import shutil
import json
import IPy
import base64
from datetime import date as datetime_date
import logging
from ipware.ip import get_client_ip

from rules.tests_rules import TestRules
from rules.validators import validate_addresses_or_networks
from rules.filter_sets import FILTER_SETS

from django.contrib.auth.models import User


request_logger = logging.getLogger('django.request')


_HUNT_FILTERS = [
    {
        'id': 'hits_min',
        'title': 'Alerts min',
        'placeholder': 'Minimum Hits Count',
        'filterType': 'number',
        'valueType': 'positiveint',
        'queryType': 'rest'
    },
    {
        'id': 'hits_max',
        'title': 'Alerts max',
        'placeholder': 'Maximum Hits Count',
        'filterType': 'number',
        'valueType': 'positiveint',
        'queryType': 'rest'
    },
    {
        'id': 'ip',
        'title': 'IP',
        'placeholder': 'Filter by IP',
        'filterType': 'text',
        'valueType': 'ip',
        'queryType': 'filter'
    },
    {
        'id': 'host',
        'title': 'Probe',
        'placeholder': 'Filter by Probes',
        'filterType': 'text',
        'valueType': 'text',
        'queryType': 'filter'
    },
    {
        'id': 'msg',
        'title': 'Message',
        'placeholder': 'Filter by Message',
        'filterType': 'text',
        'valueType': 'text',
        'queryType': 'filter'
    },
    {
        'id': 'not_in_msg',
        'title': 'Not in Message',
        'placeholder': 'Filter by not in Message',
        'filterType': 'text',
        'valueType': 'text',
        'queryType': 'filter'
    },
    {
        'id': 'content',
        'title': 'Content',
        'placeholder': 'Filter by Content',
        'filterType': 'text',
        'valueType': 'text',
        'queryType': 'rest'
    },
    {
        'id': 'not_in_content',
        'title': 'Not in Content',
        'placeholder': 'Filter by not in Content',
        'filterType': 'text',
        'valueType': 'text',
        'queryType': 'rest'
    },
    {
        'id': 'port',
        'title': 'Port',
        'placeholder': 'Filter by Port (src/dest)',
        'filterType': 'number',
        'valueType': 'positiveint',
        'queryType': 'filter'
    },
    {
        'id': 'alert.signature_id',
        'title': 'Signature ID',
        'placeholder': 'Filter by Signature ID',
        'filterType': 'number',
        'valueType': 'positiveint',
        'queryType': 'filter'
    },
    {
        'id': 'es_filter',
        'title': 'ES Filter',
        'placeholder': 'Free ES Filter',
        'filterType': 'text',
        'valueType': 'text',
        'queryType': 'filter'
    },
    {
        'id': 'protocol',
        'title': 'Protocol',
        'placeholder': 'Filter by Protocol',
        'filterType': 'complex-select-text',
        'filterCategoriesPlaceholder': 'Filter by type',
        'queryType': 'filter',
        'filterCategories': [
            {
                'id': 'dns',
                'title': 'DNS',
                'filterValues': [
                    {'id': 'query.rrname', 'title': 'Query Name'},
                    {'id': 'query.rrtype', 'title': 'Query Type'},
                ]
            },
            {
                'id': 'http',
                'title': 'HTTP',
                'filterValues': [
                    {'id': 'http_user_agent', 'title': 'User-Agent', 'placeholder': 'Filter by User Agent'},
                    {'id': 'hostname', 'title': 'Host', 'placeholder': 'Filter by Host'},
                    {'id': 'url', 'title': 'URL', 'placeholder': 'Filter by URL'},
                    {'id': 'status', 'title': 'Status', 'placeholder': 'Filter by Status'},
                    {'id': 'http_method', 'title': 'Method', 'placeholder': 'Filter by Method'},
                    {'id': 'http_content_type', 'title': 'Content Type', 'placeholder': 'Filter by Content Type'},
                    {'id': 'length', 'title': 'Length', 'placeholder': 'Filter by Content Length'},
                ]
            },
            {
                'id': 'smtp',
                'title': 'SMTP',
                'filterValues': [
                    {'id': 'mail_from', 'title': 'From', 'placeholder': 'Filter by From'},
                    {'id': 'rcpt_to', 'title': 'To', 'placeholder': 'Filter by To'},
                    {'id': 'helo', 'title': 'Helo', 'placeholder': 'Filter by Helo'}
                ]
            },
            {
                'id': 'smb',
                'title': 'SMB',
                'filterValues': [
                    {'id': 'command', 'title': 'Command', 'placeholder': 'Filter by Command'},
                    {'id': 'status', 'title': 'Status', 'placeholder': 'Filter by Status'},
                    {'id': 'filename', 'title': 'Filename', 'placeholder': 'Filter by Filename'},
                    {'id': 'share', 'title': 'Share', 'placeholder': 'Filter by Share'}
                ]
            },
            {
                'id': 'ssh',
                'title': 'SSH',
                'filterValues': [
                    {'id': 'client.software_version', 'title': 'Client Software', 'placeholder': 'Filter by Client Software'},
                    {'id': 'client.proto_version', 'title': 'Client Version', 'placeholder': 'Filter by Client Version'},
                    {'id': 'server.software_version', 'title': 'Server Software', 'placeholder': 'Filter by Server Software'},
                    {'id': 'server.proto_version', 'title': 'Server Version', 'placeholder': 'Filter by Server Version'},
                ]
            },
            {
                'id': 'tls',
                'title': 'TLS',
                'filterValues': [
                    {'id': 'subject', 'title': 'Subject DN', 'placeholder': 'Filter by Subject DN'},
                    {'id': 'issuerdn', 'title': 'Issuer DN', 'placeholder': 'Filter by Issuer DN'},
                    {'id': 'sni', 'title': 'Server Name Indication', 'placeholder': 'Filter by Server Name Indication'},
                    {'id': 'version', 'title': 'Version', 'placeholder': 'Filter by Version'},
                    {'id': 'fingerprint', 'title': 'Fingerprint', 'placeholder': 'Filter by Fingerprint'},
                    {'id': 'serial', 'title': 'Serial', 'placeholder': 'Filter by Serial'},
                    {'id': 'ja3.hash', 'title': 'JA3 Hash', 'placeholder': 'Filter by JA3 Hash'},
                    {'id': 'ja3s.hash', 'title': 'JA3S Hash', 'placeholder': 'Filter by JA3S Hash'},
                ]
            },
        ]
    }
]


def get_hunt_filters():
    return deepcopy(_HUNT_FILTERS)


def validate_source_datatype(datatype):
    from scirius.utils import get_middleware_module
    extra_types = get_middleware_module('common').update_source_content_type()
    datatypes = [ct[0] for ct in Source.CONTENT_TYPE + extra_types]
    if datatype not in datatypes:
        if datatype in get_middleware_module('common').custom_source_datatype():
            if Source.objects.filter(datatype='threat').count() > 0:
                raise ValidationError('You cannot add more than 1 "%s" source' % datatype)
        else:
            raise ValidationError('Invalid data type "%s", must be one of %s' % (datatype, ', '.join(sorted(datatypes))))


def validate_hostname(val):
    try:
        validate_ipv4_address(val)
    except ValidationError:
        # ip may in fact be a hostname
        # http://www.regextester.com/23
        HOSTNAME_RX = r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$'
        if not re.match(HOSTNAME_RX, val):
            raise ValidationError('Invalid hostname or IP')


def validate_port(val):
    try:
        val = int(val)
    except ValueError:
        raise ValidationError('Invalid port')


def validate_proxy(val):
    if val.startswith('http://') or val.startswith('https://'):
        val = val.rstrip('/')
        if val.startswith('http://'):
            val = val[len('http://'):]
        else:
            val = val[len('https://'):]

        if '@' in val:
            login, val = val.rsplit('@', 1)
            if login.count(':') < 1:
                raise ValidationError('Invalid login, no password found')

    if val.count(':') != 1:
        raise ValidationError('Invalid address')

    host, port = val.split(':')
    validate_hostname(host)
    validate_port(port)


def validate_url(val):
    # URL validator that does not require a FQDN
    if not (val.startswith('http://') or val.startswith('https://')):
        raise ValidationError('Invalid scheme')

    netloc = val.split('://', 1)[1]
    if '/' in netloc:
        netloc = netloc.split('/', 1)[0]

    if '@' in netloc:
        netloc = netloc.split('@', 1)[1]

    if ':' in netloc:
        netloc, port = netloc.split(':', 1)
        validate_port(port)

    validate_hostname(netloc)


def validate_url_list(value):
    for url in value.split(','):
        validate_url(url)


class FakePermissionModel(models.Model):
    '''
    This fake model with no database table will generate a contenttype id
    that will be used with all permissions.
    This way, permissions are not linked with models.
    Ref: https://stackoverflow.com/questions/13932774/how-can-i-use-django-permissions-without-defining-a-content-type-or-model
    '''

    class Meta:
        managed = False
        default_permissions = ()


class FilterSet(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, null=True)
    content = models.TextField()
    name = models.CharField(max_length=150)
    page = models.CharField(max_length=25)
    description = models.TextField(blank=True, null=True)
    imported = models.BooleanField(default=False)

    @staticmethod
    def get_default_filter_sets():
        return FILTER_SETS


class UserAction(models.Model):
    ACTIONS = OrderedDict([
        # Login/Logout
        ('create_user', {
            'description': '{user} has created new user {new_user}',
            'title': 'Create User',
            'perm': 'rules.configuration_auth'
        }),
        ('edit_user', {
            'description': '{user} has edited user {other_user}',
            'title': 'Edit User',
            'perm': 'rules.configuration_auth'
        }),
        ('edit_user_token', {
            'description': '{user} has edited {other_user} token',
            'title': 'Edit User Token',
            'perm': 'rules.configuration_auth'
        }),
        ('edit_user_password', {
            'description': '{user} has edited {other_user} password',
            'title': 'Edit User Password',
            'perm': 'rules.configuration_auth'
        }),
        ('delete_user', {
            'description': '{user} has deleted user {old_user}',
            'title': 'Delete User',
            'perm': 'rules.configuration_auth'
        }),
        ('create_group', {
            'description': '{user} has created new role {new_group}',
            'title': 'Create Role',
            'perm': 'rules.configuration_auth'
        }),
        ('edit_group', {
            'description': '{user} has edited role {group}',
            'title': 'Edit Role',
            'perm': 'rules.configuration_auth'
        }),
        ('delete_group', {
            'description': '{user} has deleted role {group}',
            'title': 'Delete Role',
            'perm': 'rules.configuration_auth'
        }),
        ('login', {
            'description': 'Logged in as {user}',
            'title': 'Login',
            'perm': 'rules.configuration_auth'
        }),
        ('logout', {
            'description': '{user} has logged out',
            'title': 'Logout',
            'perm': 'rules.configuration_auth'
        }),

        # Sources:
        ('create_source', {
            'description': '{user} has created source {source}',
            'title': 'Create Source',
            'perm': 'rules.source_view'
        }),
        ('update_source', {
            'description': '{user} has updated source {source}',
            'title': 'Update Source',
            'perm': 'rules.source_view'
        }),
        ('edit_source', {
            'description': '{user} has edited source {source}',
            'title': 'Edit Source',
            'perm': 'rules.source_view'
        }),
        ('upload_source', {
            'description': '{user} has uploaded source {source}',
            'title': 'Upload Source',
            'perm': 'rules.source_view'
        }),
        ('enable_source', {
            'description': '{user} has enabled source {source} in ruleset {ruleset}',
            'title': 'Enable Source',
            'perm': 'rules.source_view'
        }),
        ('disable_source', {
            'description': '{user} has disabled source {source} in ruleset {ruleset}',
            'title': 'Disable Source',
            'perm': 'rules.source_view'
        }),
        ('delete_source', {
            'description': '{user} has deleted source {source}',
            'title': 'Delete Source',
            'perm': 'rules.source_view'
        }),

        # Rulesets:
        ('create_ruleset', {
            'description': '{user} has created ruleset {ruleset}',
            'title': 'Create Ruleset',
            'perm': 'rules.source_view'
        }),
        ('transform_ruleset', {
            'description': '{user} has transformed ruleset {ruleset} to {transformation}',
            'title': 'Transform Ruleset',
            'perm': 'rules.source_view'
        }),
        ('edit_ruleset', {
            'description': '{user} has edited ruleset {ruleset}',
            'title': 'Edit Ruleset',
            'perm': 'rules.source_view'
        }),
        ('copy_ruleset', {
            'description': '{user} has copied ruleset {ruleset}',
            'title': 'Copy Ruleset',
            'perm': 'rules.source_view'
        }),
        ('delete_ruleset', {
            'description': '{user} has deleted ruleset {ruleset}',
            'title': 'Delete Ruleset',
            'perm': 'rules.source_view'
        }),

        # Categories:
        ('enable_category', {
            'description': '{user} has enabled category {category} in ruleset {ruleset}',
            'title': 'Enable Category',
            'perm': 'rules.ruleset_policy_view'
        }),
        ('transform_category', {
            'description': '{user} has transformed category {category} to {transformation} in ruleset {ruleset}',
            'title': 'Transform Category',
            'perm': 'rules.ruleset_policy_view'
        }),
        ('disable_category', {
            'description': '{user} has disabled category {category} in ruleset {ruleset}',
            'title': 'Disable Category',
            'perm': 'rules.ruleset_policy_view'
        }),

        # Rules:
        ('enable_rule', {
            'description': '{user} has enabled rule {rule} in ruleset {ruleset}',
            'title': 'Enable Rule',
            'perm': 'rules.ruleset_policy_view'
        }),
        ('comment_rule', {
            'description': '{user} has commented rule {rule}',
            'title': 'Comment Rule',
            'perm': 'rules.ruleset_policy_view'
        }),
        ('transform_rule', {
            'description': '{user} has transformed rule {rule} to {transformation} in ruleset {ruleset}',
            'title': 'Transform Rule',
            'perm': 'rules.ruleset_policy_view'
        }),
        ('suppress_rule', {
            'description': '{user} has suppressed rule {rule} in ruleset {ruleset}',
            'title': 'Suppress Rule',
            'perm': 'rules.ruleset_policy_view'
        }),
        ('disable_rule', {
            'description': '{user} has disabled rule {rule} in ruleset {ruleset}',
            'title': 'Disable Rule',
            'perm': 'rules.ruleset_policy_view'
        }),
        ('delete_suppress_rule', {
            'description': '{user} has deleted suppressed rule {rule} in ruleset {ruleset}',
            'title': 'Delete Suppress Rule',
            'perm': 'rules.ruleset_policy_view'
        }),

        # Toggle availability
        ('toggle_availability', {
            'description': '{user} has modified rule availability {rule}',
            'title': 'Toggle Availability',
            'perm': 'rules.ruleset_policy_view'
        }),

        # Thresholds:
        ('create_threshold', {
            'description': '{user} has created threshold on rule {rule} in ruleset {ruleset}',
            'title': 'Create Threshold',
            'perm': 'rules.ruleset_policy_view'
        }),
        ('edit_threshold', {
            'description': '{user} has edited threshold {threshold} on rule {rule} in ruleset {ruleset}',
            'title': 'Edit Threshold',
            'perm': 'rules.ruleset_policy_view'
        }),
        ('delete_threshold', {
            'description': '{user} has deleted threshold {threshold} on rule {rule} in ruleset {ruleset}',
            'title': 'Delete Threshold',
            'perm': 'rules.ruleset_policy_view'
        }),

        # Used only in REST API
        ('delete_transform_ruleset', {
            'description': '{user} has deleted transformation {transformation} on ruleset {ruleset}',
            'title': 'Deleted Ruleset Transformation',
            'perm': 'rules.ruleset_policy_view'
        }),
        ('delete_transform_rule', {
            'description': '{user} has deleted transformation {transformation} on rule {rule} in ruleset {ruleset}',
            'title': 'Delete Rule Transformation',
            'perm': 'rules.ruleset_policy_view'
        }),
        ('delete_transform_category', {
            'description': '{user} has deleted transformation {transformation} on category {category} in ruleset {ruleset}',
            'title': 'Delete Category Transformation',
            'perm': 'rules.ruleset_policy_view'
        }),
        # End REST API

        # Suricata
        ('edit_suricata', {
            'description': '{user} has edited suricata',
            'title': 'Edit Suricata',
            'perm': 'rules.configuration_view'
        }),
        ('create_suricata', {
            'description': '{user} has created suricata',
            'title': 'Create Suricata',
            'perm': 'rules.configuration_view'
        }),
        ('update_push_all', {
            'description': '{user} has pushed ruleset {ruleset}',
            'title': 'Update/Push ruleset',
            'perm': 'rules.ruleset_update_push'
        }),

        # Settings
        ('system_settings', {
            'description': '{user} has edited system settings',
            'title': 'Edit System Settings',
            'perm': 'rules.configuration_view'
        }),
        ('delete_alerts', {
            'description': '{user} has deleted alerts from rule {rule}',
            'title': 'Delete Alerts',
            'perm': 'rules.events_view'
        }),

        # Rule processing filter
        ('create_rule_filter', {
            'description': '{user} has created rule filter {rule_filter} in ruleset {ruleset}',
            'title': 'Create rule filter',
            'perm': 'rules.events_view'
        }),
        ('edit_rule_filter', {
            'description': '{user} has edited rule filter {rule_filter} in ruleset {ruleset}',
            'title': 'Edit rule filter',
            'perm': 'rules.events_view'
        }),
        ('delete_rule_filter', {
            'description': '{user} has deleted rule filter {rule_filter} in ruleset {ruleset}',
            'title': 'Delete rule filter',
            'perm': 'rules.events_view'
        })
    ])

    action_type = models.CharField(max_length=1000, null=True)
    date = models.DateTimeField('event date', default=timezone.now)
    comment = models.TextField(null=True, blank=True)
    user = models.ForeignKey(User, default=None, on_delete=models.SET_NULL, null=True, blank=True)
    username = models.CharField(max_length=150)
    ua_objects = GenericRelation('UserActionObject', related_query_name='ua_objects')
    # Compatibilty
    description = models.CharField(max_length=1512, null=True)
    client_ip = models.CharField(max_length=64, blank=True, null=True)

    def __init__(self, *args, **kwargs):
        super(UserAction, self).__init__(*args, **kwargs)
        if not self.username and self.user:
            self.username = self.user.username

    def __str__(self):
        return self.generate_description()

    @staticmethod
    def get_allowed_actions_type(request):
        from scirius.utils import get_middleware_module
        actions_dict = get_middleware_module('common').get_user_actions_dict()

        actions = []
        for action_type, val in actions_dict.items():
            perm = val.get('perm', 'no_perm')
            if request.user.has_perm(perm):
                actions.append(action_type)
        return actions

    @staticmethod
    def _get_request_info(request):
        user = request.user
        if user.__class__.__name__ == 'FakeUser' and settings.DEBUG:
            user = User.objects.first()
        return user, get_client_ip(request)[0]

    @classmethod
    def create(cls, **kwargs):
        if 'action_type' not in kwargs:
            raise Exception('Cannot create UserAction without "action_type"')

        if 'request' in kwargs:
            user, ip = cls._get_request_info(kwargs['request'])
            kwargs.pop('request')
            kwargs.update({
                'user': user,
                'client_ip': ip
            })

        force_insert = True if 'force_insert' in kwargs and kwargs.pop('force_insert') else False

        # UserAction
        ua_params = {}
        for param in ('action_type', 'comment', 'user', 'date', 'client_ip'):
            if param in kwargs:
                ua_params[param] = kwargs.pop(param)

        ua = cls(**ua_params)
        ua.save(force_insert)

        # UserActionObject
        for action_key, action_value in kwargs.items():

            ua_obj_params = {
                'action_key': action_key,
                'action_value': str(action_value)[:100],
                'user_action': ua,
            }

            if not isinstance(action_value, str):
                ua_obj_params['content'] = action_value

            ua_obj = UserActionObject(**ua_obj_params)
            ua_obj.save()

        # Used as test
        ua.generate_description(ua_params['user'])

        # Warning; do not remove.
        # hack callback is called after UserAction.save is called. So the
        # 2nd save will trigger the callback, once UserActionObject
        # have been created
        ua.save()

    @staticmethod
    def _is_action_authorized(action_key, user):
        if user:
            if action_key == 'ruleset' or action_key == 'source':
                if user.has_perm('rules.ruleset_policy_view'):
                    return True
                return False

        return True

    def generate_description(self, user=None):
        if self.description:
            return self.description

        from scirius.utils import get_middleware_module
        actions_dict = get_middleware_module('common').get_user_actions_dict()
        if self.action_type not in list(actions_dict.keys()):
            raise Exception('Unknown action type "%s"' % self.action_type)

        format_ = {'user': format_html('<strong>{}</strong>', self.username), 'datetime': self.date}
        actions = UserActionObject.objects.filter(user_action=self).all()

        for action in actions:
            if action.content and hasattr(action.content, 'get_absolute_url') and self._is_action_authorized(action.action_key, user):
                format_[action.action_key] = format_html('<a href="{}"><strong>{}</strong></a>',
                                                         action.content.get_absolute_url(),
                                                         action.action_value)
            else:
                format_[action.action_key] = format_html('<strong>{}</strong>', action.action_value)

        try:
            html = format_html(actions_dict[self.action_type]['description'], **format_)
        except KeyError:
            # bug compatibility: workaround for action_value > 100
            # UserActionObjects related to UserAction (self) were
            # not inserted on creation
            html = ''
        return html

    def get_title(self):
        if self.description:
            return self.description[:15]

        from scirius.utils import get_middleware_module
        actions_dict = get_middleware_module('common').get_user_actions_dict()
        if self.action_type not in list(actions_dict.keys()):
            raise Exception('Unknown action type "%s"' % self.action_type)

        return actions_dict[self.action_type]['title']

    @staticmethod
    def get_icon():
        return 'pficon-user'

    def get_icons(self):
        actions = UserActionObject.objects.filter(user_action=self).all()
        icons = [(self.get_icon(), self.username)]

        for action in actions:

            # ==== Coner cases
            # transformation is str type
            # or workaround for UserAction which can contains no instance but str (ex: create a source without a ruleset)
            if action.action_key == 'transformation' or \
                    (action.action_key == 'ruleset' and action.action_value == 'No Ruleset') or \
                    action.action_key == 'threat_status':
                continue

            ct = action.content_type
            klass = ct.model_class()

            if hasattr(klass, 'get_icon'):
                lb = action.action_value

                icon = klass.get_icon()
                instance = klass.objects.filter(pk=action.object_id).first()

                if instance:
                    if isinstance(instance, Source):
                        icon = Source.get_icon(instance)

                    if isinstance(instance, Rule):
                        lb = instance.pk

                    if isinstance(instance, RuleProcessingFilter) and instance.action == 'threat':
                        lb = instance.threatmethod.threat.name

                icons.append((icon, lb))

        html = format_html_join(
            '\n', '<div class="list-view-pf-additional-info-item"><span class="fa {}"></span>{}</div>',
            ((icon, klass_name) for icon, klass_name in icons)
        )

        return html

    @staticmethod
    def get_user_actions_dict():
        return deepcopy(UserAction.ACTIONS)


class SystemSettings(models.Model):
    use_http_proxy = models.BooleanField(default=False)
    http_proxy = models.CharField(
        max_length=200,
        validators=[validate_proxy],
        default="",
        blank=True,
        help_text='Proxy address of the form "host:port".'
    )
    https_proxy = models.CharField(max_length=200, validators=[validate_proxy], default="", blank=True)
    use_elasticsearch = models.BooleanField(default=True)
    custom_elasticsearch = models.BooleanField(default=False)
    elasticsearch_url = models.CharField(
        max_length=4096,
        validators=[validate_url_list],
        blank=False,
        null=False,
        default='http://elasticsearch:9200/',
        help_text='Comma separated list of elasticsearch url'
    )
    use_proxy_for_es = models.BooleanField(default=False)
    custom_cookie_age = models.FloatField('Age of session cookies', default=360)
    elasticsearch_user = models.CharField('Elasticsearch username', max_length=4096, blank=True, default='')
    elasticsearch_pass = models.CharField('Elasticsearch password', max_length=4096, blank=True, default='')
    custom_login_banner = models.TextField('Add your own banner on login page', blank=True, default='')

    def get_proxy_params(self):
        if self.use_http_proxy:
            return {'http': self.http_proxy, 'https': self.https_proxy}
        else:
            return None


def get_system_settings():
    gsettings = SystemSettings.objects.all()
    if len(gsettings):
        return gsettings[0]
    else:
        gsettings = SystemSettings.objects.create()
        if settings.USE_ELASTICSEARCH:
            gsettings.use_elasticsearch = True
        else:
            gsettings.use_elasticsearch = False
        if settings.USE_PROXY:
            gsettings.use_http_proxy = True
            gsettings.http_proxy = settings.PROXY_PARAMS['http']
            gsettings.https_proxy = settings.PROXY_PARAMS['https']
        else:
            gsettings.use_http_proxy = False
        gsettings.save()
        return gsettings


def get_es_address():
    from rules.es_query import ESQuery
    return ESQuery.get_es_address()


class InvalidCategoryException(Exception):
    pass


class Source(models.Model):
    FETCH_METHOD = (
        ('http', 'HTTP URL'),
        # ('https', 'HTTPS URL'),
        ('local', 'Upload'),
    )
    CONTENT_TYPE = [
        ('sigs', 'Signatures files in tar archive'),
        ('sig', 'Individual Signatures file'),
        # ('iprep', 'IP reputation files'),
        ('other', 'Other content'),
        ('b64dataset', 'String dataset file'),
    ]
    TMP_DIR = "/tmp/"
    REFRESH_LOCK_ID = 'source-lock'
    REFRESH_LOCK_EXPIRE = 60 * 10

    name = models.CharField(max_length=100, unique=True)
    created_date = models.DateTimeField('date created')
    updated_date = models.DateTimeField('date updated', blank=True, null=True)
    method = models.CharField(max_length=10, choices=FETCH_METHOD)
    datatype = models.CharField(max_length=10)
    uri = models.CharField(max_length=400, blank=True, null=True)
    cert_verif = models.BooleanField('Check certificates', default=True)
    authkey = models.CharField(max_length=400, blank=True, null=True)
    public_source = models.CharField(max_length=100, blank=True, null=True)
    use_iprep = models.BooleanField('Use IP reputation for group signatures', default=True)
    version = models.IntegerField(default=1)
    use_sys_proxy = models.BooleanField(default=True, verbose_name='Use system proxy')
    untrusted = models.BooleanField(default=True, verbose_name='Source sanitization')

    editable = True
    # git repo where we store the physical thing
    # this allow to store the different versions
    # and to checkout the sources to a given version
    # for ruleset generation
    # Operations
    #  - Create
    #  - Delete
    #  - Update: only custom one
    #    Use method to get new files and commit them
    #    Create a new SourceAtVersion when there is a real update
    #    In case of upload: simply propose user upload form

    @classmethod
    def get_sources(cls):
        return cls.objects.annotate(
            cats_count=models.Count('category', distinct=True),
            rules_count=models.Count('category__rule')
        ).order_by('name')

    def save(self, *args, **kwargs) -> None:
        # creation
        if self._state.adding:
            validate_source_datatype(self.datatype)
        if self.datatype in self.custom_data_type:
            if self.use_iprep:
                self.use_iprep = False
            if self.untrusted:
                self.untrusted = False
        return super().save(*args, **kwargs)

    def __init__(self, *args, **kwargs):
        models.Model.__init__(self, *args, **kwargs)
        if (self.method == 'http'):
            self.update_ruleset = self.update_ruleset_http
        else:
            self.update_ruleset = None
        self.first_run = False
        self.updated_rules = {"added": [], "deleted": [], "updated": []}

        from scirius.utils import get_middleware_module
        self.custom_data_type = get_middleware_module('common').custom_source_datatype()

    @staticmethod
    def get_icon(instance=None):
        if instance:
            if instance.method == 'http':
                return 'fa fa-external-link list-view-pf-icon-sm'
        return 'pficon pficon-volume list-view-pf-icon-sm'

    def delete(self):
        self.needs_test()
        # delete git tree
        source_git_dir = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.pk))
        try:
            shutil.rmtree(source_git_dir)
        # Ignore error if not present
        except OSError:
            pass
        # delete model
        models.Model.delete(self)

    def __str__(self):
        return self.name

    def aggregate_update(self, update):
        self.updated_rules["added"] = list(set(self.updated_rules["added"]).union(set(update["added"])))
        self.updated_rules["deleted"] = list(set(self.updated_rules["deleted"]).union(set(update["deleted"])))
        self.updated_rules["updated"] = list(set(self.updated_rules["updated"]).union(set(update["updated"])))

    def get_categories(self, sversion):
        source_git_dir = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.pk))
        catname = re.compile(r"(.+)\.rules$")
        re_version = re.compile(r'(\w+)-u(\d+)\.rules$')

        existing_rules_hash = {}
        for rule in Rule.objects.all().prefetch_related('category'):
            if rule.sid not in existing_rules_hash:
                existing_rules_hash[rule.sid] = {}

            for rav in rule.ruleatversion_set.all():
                existing_rules_hash[rule.sid][rav.version] = rav

        for f in os.listdir(os.path.join(source_git_dir, 'rules')):
            if f.endswith('.rules'):
                match = catname.search(f)
                version_match = re_version.search(f)
                name = match.groups()[0] if not version_match else version_match.group(1)
                version = int(version_match.group(2)) if version_match else 0

                category = Category.objects.filter(source=self, name=name)
                if not category:
                    category = Category.objects.create(
                        source=self,
                        name=name,
                        created_date=timezone.now(),
                        filename=os.path.join('rules', '%s.rules' % name)
                    )
                    for ruleset in sversion.ruleset_set.all():
                        if ruleset.activate_categories:
                            ruleset.categories.add(category)
                else:
                    category = category[0]
                category.get_rules(
                    self,
                    version=version,
                    filename=os.path.join('rules', f),
                    existing_rules_hash=existing_rules_hash)
                # get rules in this category
        for category in Category.objects.filter(source=self):
            if not os.path.isfile(os.path.join(source_git_dir, category.filename)):
                category.delete()

    def get_git_repo(self, delete=False):
        # check if git tree is in place
        source_git_dir = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.pk))
        if not os.path.isdir(source_git_dir):
            if os.path.isfile(source_git_dir):
                raise OSError("git-sources is not a directory")
            os.makedirs(source_git_dir)
            repo = git.Repo.init(source_git_dir)
            config = repo.config_writer()
            config.set_value("user", "email", "scirius@stamus-networks.com")
            config.set_value("user", "name", "Scirius")
            del config
            del repo
            repo = git.Repo(source_git_dir)
            self.first_run = True
        else:
            if delete:
                try:
                    shutil.rmtree(os.path.join(source_git_dir, "rules"))
                except OSError:
                    print("Can not delete directory")
                    pass
            repo = git.Repo(source_git_dir)
        return repo

    def create_sourceatversion(self, version='HEAD'):
        # look for SourceAtVersion with name and HEAD
        # Update updated_date
        sversions = SourceAtVersion.objects.filter(source=self, version=version)
        sversion = sversions.first()
        if sversion:
            sversion.updated_date = self.updated_date
            sversion.save()
        else:
            sversion = SourceAtVersion.objects.create(
                source=self,
                version=version,
                updated_date=self.updated_date,
                git_version=version
            )

        return sversion

    def _check_category_ids(self, f, filename, field_no):
        # Check the file object in argument does not contain category ids < 20
        for line_no, line in enumerate(f.readlines()):
            try:
                line = line.strip()

                if not line or line.startswith(b'#'):
                    continue
                fields = line.split(b',')

                cat_no = int(fields[field_no])
                if cat_no < 20:
                    raise InvalidCategoryException('Invalid category %i in %s (line %i): category < 20 are reserved to Scirius' % (cat_no, filename, line_no + 1))
            except (IndexError, ValueError):
                raise Exception('Invalid syntax in file %s (line %i)' % (filename, line_no + 1))

    # Rewrite of https://github.com/python/cpython/blob/master/Lib/tarfile.py
    # Extract tar file but force setting permissions
    @staticmethod
    def _tar_extractall(tarfile, path=".", members=None, *, numeric_owner=False):
        if members is None:
            members = tarfile

        for tarinfo in members:
            tarfile.extract(tarinfo, path, set_attrs=False)
            fpath = os.path.join(path, tarinfo.name)

            if tarinfo.isdir():
                os.chmod(fpath, 0o755)
            else:
                os.chmod(fpath, 0o644)

    def handle_rules_in_tar(self, f):
        f.seek(0)
        if (not tarfile.is_tarfile(f.name)):
            raise OSError("Invalid tar file")

        self.updated_date = timezone.now()
        self.first_run = False

        repo = self.get_git_repo(delete=True)

        f.seek(0)
        # extract file
        tfile = tarfile.open(fileobj=f)
        dir_list = []
        rules_dir = None

        for member in tfile.getmembers():
            # only file and dir are allowed
            if not (member.isfile() or member.isdir()):
                raise SuspiciousOperation("Suspect tar file contains non regular file '%s'" % (member.name))

            if member.name.startswith('/') or '..' in member.name:
                raise SuspiciousOperation("Suspect tar file contains invalid path '%s'" % (member.name))

            if member.isdir() and ('/' + member.name).endswith('/rules'):
                if rules_dir:
                    raise SuspiciousOperation("Tar file contains two 'rules' directory instead of one")
                dir_list.append(member)
                rules_dir = member.name

            if member.isfile():
                # we now allow "rules" files even if they are at root directory
                member.name = os.path.join('rules', os.path.basename(member.name))
                dir_list.append(member)

                if member.name.endswith('categories.txt'):
                    f = tfile.extractfile(member.name)
                    self._check_category_ids(f, member.name, 0)

                if member.name.endswith('.list'):
                    f = tfile.extractfile(member.name)
                    self._check_category_ids(f, member.name, 1)

        source_git_dir = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.pk))
        self._tar_extractall(tfile, path=source_git_dir, members=dir_list)

        index = repo.index
        if len(index.diff(None)) or self.first_run:
            os.environ['USERNAME'] = 'scirius'
            index.add(['rules'])
            message = 'source version at %s' % (self.updated_date)
            index.commit(message)

        self.save()
        # Now we must update SourceAtVersion for this source
        # or create it if needed
        sversion = self.create_sourceatversion()
        # Get categories
        self.get_categories(sversion)

    def handle_other_file(self, f, b64encode=False):
        self.updated_date = timezone.now()
        self.first_run = False
        repo = self.get_git_repo(delete=True)
        rules_dir = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.pk), 'rules')

        # create rules dir if needed
        if not os.path.isdir(rules_dir):
            os.makedirs(rules_dir)

        f.seek(0)
        if b64encode is False:
            # copy file content to target
            os.fsync(f)
            shutil.copy(f.name, os.path.join(rules_dir, self.name))
        else:
            target_file = os.path.join(rules_dir, self.name)
            with open(target_file, 'wb') as tf:
                for stringelt in f:
                    tf.write(base64.b64encode(stringelt.rstrip(b'\r\n')) + b"\n")

        index = repo.index
        if len(index.diff(None)) or self.first_run:
            os.environ['USERNAME'] = 'scirius'
            index.add(['rules'])
            message = 'source version at %s' % (self.updated_date)
            index.commit(message)

        self.save()
        # Now we must update SourceAtVersion for this source
        # or create it if needed
        self.create_sourceatversion()

    def handle_b64dataset(self, f):
        return self.handle_other_file(f, b64encode=True)

    def handle_rules_file(self, f):
        f.seek(0)
        if (tarfile.is_tarfile(f.name)):
            raise OSError("This is a tar file and not a individual signature file, please select another category")
        f.seek(0)

        self.updated_date = timezone.now()
        self.first_run = False
        repo = self.get_git_repo(delete=True)
        rules_dir = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.pk), 'rules')

        # create rules dir if needed
        if not os.path.isdir(rules_dir):
            os.makedirs(rules_dir)

        # copy file content to target
        f.seek(0)
        os.fsync(f)
        shutil.copy(f.name, os.path.join(rules_dir, 'sigs.rules'))

        index = repo.index
        if len(index.diff(None)) or self.first_run:
            os.environ['USERNAME'] = 'scirius'
            index.add(["rules"])
            message = 'source version at %s' % (self.updated_date)
            index.commit(message)

        self.save()

        # Now we must update SourceAtVersion for this source
        # or create it if needed
        self.create_sourceatversion()
        # category based on filename
        category = Category.objects.filter(source=self, name=('%s Sigs' % (self.name))[:100])
        if not category:
            category = Category.objects.create(
                source=self,
                name=('%s Sigs' % (self.name))[:100],
                created_date=timezone.now(),
                filename=os.path.join('rules', 'sigs.rules')
            )
            category.get_rules(self)
        else:
            category = category[0]

        category.get_rules(self)
        if len(Rule.objects.filter(category=category)) == 0:
            category.delete()
            raise ValidationError('The source %s contains no valid signature' % self.name)

    def handle_custom_file(self, f, upload=False):
        from scirius.utils import get_middleware_module

        f.seek(0)
        if not tarfile.is_tarfile(f.name):
            raise OSError("Invalid tar file")

        self.first_run = False
        self.updated_date = timezone.now()
        repo = self.get_git_repo(delete=True)
        sources_dir = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.pk))
        version_path = os.path.join(sources_dir, 'rules', 'version.txt')

        # create rules dir if needed
        if not os.path.isdir(sources_dir):
            os.makedirs(sources_dir)

        f.seek(0)
        get_middleware_module('common').extract_custom_source(f, sources_dir)
        if upload:
            sources_path = os.path.join(sources_dir, 'rules')
            get_middleware_module('common').update_custom_source(sources_path)

        index = repo.index
        if len(index.diff(None)) or self.first_run:
            os.environ['USERNAME'] = 'scirius'
            index.add(['rules'])
            message = 'source version at %s' % self.updated_date
            index.commit(message)

        with open(version_path, 'r') as f:
            self.version = int(f.read())

        self.save()
        # Now we must update SourceAtVersion for this source
        # or create it if needed
        sversion = self.create_sourceatversion()
        self.get_categories(sversion)

    def json_rules_list(self, rlist):
        rules = []
        for rule in rlist:
            rules.append({
                "sid": rule.sid,
                "msg": rule.msg,
                "category": rule.category.name,
                "pk": rule.pk}
            )
        # for each rule we create a json object sid + msg + content
        return rules

    def create_update(self):
        # for each set
        update = {}
        update["deleted"] = self.json_rules_list(self.updated_rules["deleted"])
        update["added"] = self.json_rules_list(self.updated_rules["added"])
        update["updated"] = self.json_rules_list(self.updated_rules["updated"])
        repo = self.get_git_repo(delete=False)
        sha = list(repo.iter_commits('master', max_count=1))[0].hexsha
        SourceUpdate.objects.create(
            source=self,
            created_date=timezone.now(),
            data=json.dumps(update),
            version=sha,
            changed=len(update["deleted"]) + len(update["added"]) + len(update["updated"]),
        )

    # This method cannot be called twice consecutively
    @transaction.atomic
    def update(self):
        # lock
        if not os.path.exists(settings.FLOCK_PATH):
            os.makedirs(settings.FLOCK_PATH)
        source_lock_path = os.path.join(settings.FLOCK_PATH, 'source_%s' % self.pk)
        source_lock = open(source_lock_path, 'w')
        fcntl.flock(source_lock, fcntl.LOCK_EX)

        try:
            # look for categories list: if none, first import
            categories = Category.objects.filter(source=self)
            firstimport = False
            if not categories:
                firstimport = True

            if self.method not in ['http', 'local']:
                raise FieldError("Currently unsupported method")

            need_update = False
            if self.update_ruleset:
                f = tempfile.NamedTemporaryFile(dir=self.TMP_DIR)
                need_update = self.update_ruleset(f)

                if need_update:
                    if self.datatype == 'sigs':
                        self.handle_rules_in_tar(f)
                    elif self.datatype == 'sig':
                        self.handle_rules_file(f)
                    elif self.datatype == 'other':
                        self.handle_other_file(f)
                    elif self.datatype == 'b64dataset':
                        self.handle_b64dataset(f)

                    if self.datatype in self.custom_data_type:
                        self.handle_custom_file(f)

            if need_update:
                if (self.datatype in ('sig', 'sigs') or self.datatype in self.custom_data_type) and not firstimport:
                    self.create_update()

                if self.datatype in self.custom_data_type:
                    from scirius.utils import get_middleware_module
                    source_path = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.pk), 'rules')
                    get_middleware_module('common').update_custom_source(source_path)

                for rule in self.updated_rules["deleted"]:
                    rule.delete()

                if self.datatype not in self.custom_data_type:
                    self.needs_test()
        finally:
            source_lock.close()

    def diff(self):
        source_git_dir = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.pk))
        if not os.path.isdir(source_git_dir):
            raise IOError("You have to update source first")

        repo = git.Repo(source_git_dir)
        hcommit = repo.head.commit
        return hcommit.diff('HEAD~1', create_patch=True)

    def export_files(self, directory, version):
        source_git_dir = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.pk))
        repo = git.Repo(source_git_dir)
        cats_content = ''
        iprep_content = ''

        datatypes = ['sig', 'sigs']
        if self.custom_data_type:
            datatypes.append(self.custom_data_type[0])

        with tempfile.TemporaryFile(dir=self.TMP_DIR) as f:
            repo.archive(f, treeish=version)
            f.seek(0)
            # extract file
            tfile = tarfile.open(fileobj=f)
            # copy file to target
            src_files = tfile.getmembers()
            for member in src_files:
                # only consider extra files in rules directory
                if not member.name.startswith('rules/'):
                    continue

                # don't copy original rules file to dest
                if member.name.endswith('.rules') and self.datatype in datatypes:
                    continue

                if member.name.endswith('categories.txt') and self.datatype in ('sig', 'sigs'):
                    cats_content = tfile.extractfile(member).read().decode()
                    continue

                if member.name.endswith('.list') and self.datatype in ('sig', 'sigs'):
                    iprep_content = tfile.extractfile(member).read().decode()
                    continue

                if member.isfile():
                    member.name = os.path.join(*member.name.split("/", 2)[1:])
                    tfile.extract(member, path=directory)
        return cats_content, iprep_content

    def get_absolute_url(self):
        return reverse('source', args=[str(self.id)])

    def is_ti_url(self):
        return self.uri.startswith('https://ti.stamus-networks.io/')

    def is_ti_dev_url(self):
        return self.uri.startswith('https://ti-dev.stamus-networks.io/')

    def is_etpro_url(self):
        return self.uri.startswith('https://rules.emergingthreatspro.com/') or \
            self.uri.startswith('https://rules.emergingthreats.net/') or \
            self.is_ti_url()

    def update_ruleset_http(self, f):
        from scirius.utils import RequestsWrapper

        hdrs = {'User-Agent': 'scirius'}
        if self.authkey:
            hdrs['Authorization'] = self.authkey

        version_uri = None
        if self.is_etpro_url() or (self.datatype not in ('sigs', 'sig', 'other', 'b64dataset') and not self.is_ti_dev_url()):
            version_uri = os.path.join(os.path.dirname(self.uri), 'version.txt')

        version_server = 1
        if version_uri:
            resp = RequestsWrapper().get(url=version_uri, headers=hdrs, verify=self.cert_verif, use_proxy=self.use_sys_proxy)
            version_server = int(resp.content.strip())

            if self.version < version_server:
                version_uri = None

        if version_uri is None:
            resp = RequestsWrapper().get(url=self.uri, headers=hdrs, verify=self.cert_verif, use_proxy=self.use_sys_proxy)
            f.write(resp.content)

            if self.version < version_server:
                self.version = version_server

            return True

        return False

    def handle_uploaded_file(self, f):
        dest = tempfile.NamedTemporaryFile(dir=self.TMP_DIR)
        for chunk in f.chunks():
            dest.write(chunk)

        dest.seek(0)
        if self.datatype == 'sigs':
            self.handle_rules_in_tar(dest)
        elif self.datatype == 'sig':
            self.handle_rules_file(dest)
        elif self.datatype == 'other':
            self.handle_other_file(dest)
        elif self.datatype == 'b64dataset':
            self.handle_b64dataset(dest)
        elif self.datatype in self.custom_data_type:
            self.handle_custom_file(dest, upload=True)

    def new_uploaded_file(self, f):
        firstimport = False
        if Category.objects.filter(source=self).count() == 0:
            firstimport = True

        self.handle_uploaded_file(f)
        if self.datatype in ('sig', 'sigs') and not firstimport:
            self.create_update()
        for rule in self.updated_rules["deleted"]:
            rule.delete()
        self.needs_test()

    def needs_test(self):
        try:
            sourceatversion = SourceAtVersion.objects.get(source=self, version='HEAD')
        except:
            return

        rulesets = Ruleset.objects.all()
        for ruleset in rulesets:
            if sourceatversion in ruleset.sources.all():
                ruleset.needs_test()


class UserActionObject(models.Model):
    action_key = models.CharField(max_length=20)
    action_value = models.CharField(max_length=100)

    user_action = models.ForeignKey(UserAction, related_name='user_action_objects', on_delete=models.CASCADE)
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, null=True)
    object_id = models.PositiveIntegerField(null=True)
    content = GenericForeignKey('content_type', 'object_id')


class SourceAtVersion(models.Model):
    source = models.ForeignKey(Source, on_delete=models.CASCADE)
    # Sha1 or HEAD or tag
    version = models.CharField(max_length=42)
    git_version = models.CharField(max_length=42, default='HEAD')
    updated_date = models.DateTimeField('date updated', blank=True, default=timezone.now)

    def __str__(self):
        return str(self.source) + "@" + self.version

    def _get_name(self):
        return str(self)

    name = property(_get_name)

    def enable(self, ruleset, request=None, comment=None):
        ruleset.sources.add(self)

        for cat in Category.objects.filter(source=self.source):
            if cat not in ruleset.categories.all():
                ruleset.categories.add(cat)

        ruleset.needs_test()
        ruleset.save()
        if request:
            UserAction.create(
                action_type='enable_source',
                comment=comment,
                request=request,
                source=self.source,
                ruleset=ruleset
            )

    def disable(self, ruleset, request=None, comment=None):
        ruleset.sources.remove(self)

        for cat in Category.objects.filter(source=self.source):
            if cat in ruleset.categories.all():
                ruleset.categories.remove(cat)

        ruleset.needs_test()
        ruleset.save()
        if request:
            UserAction.create(
                action_type='disable_source',
                comment=comment,
                request=request,
                source=self.source,
                ruleset=ruleset
            )

    def export_files(self, directory):
        return self.source.export_files(directory, self.version)

    def to_buffer(self):
        categories = Category.objects.filter(source=self.source)
        rules = Rule.objects.filter(category__in=categories)
        file_content = "# Rules file for %s generated by Scirius at %s\n" % (self.name, str(timezone.now()))
        rules_content = [rule.ruleatversion_set.first().content for rule in rules]
        file_content += "\n".join(rules_content)
        return file_content

    def test_rule_buffer(self, rule_buffer, single=False):
        testor = TestRules()
        tmpdir = tempfile.mkdtemp()
        cats_content, iprep_content = self.export_files(tmpdir)
        related_files = {}

        for root, _, files in os.walk(tmpdir):
            for f in files:
                fullpath = os.path.join(root, f)
                if os.path.getsize(fullpath) < 50 * 1024:
                    with open(fullpath, 'r') as cf:
                        related_files[f] = cf.read()
        shutil.rmtree(tmpdir)

        return testor.check_rule_buffer(
            rule_buffer,
            related_files=related_files,
            single=single,
            cats_content=cats_content,
            iprep_content=iprep_content
        )

    def test(self):
        rule_buffer = self.to_buffer()
        return self.test_rule_buffer(rule_buffer)


class SourceUpdate(models.Model):
    source = models.ForeignKey(Source, on_delete=models.CASCADE)
    created_date = models.DateTimeField('date of update', blank=True, default=timezone.now)
    # Store update info as a JSON document
    data = models.TextField()
    version = models.CharField(max_length=42)
    changed = models.IntegerField(default=0)

    def diff(self):
        data = json.loads(self.data)
        diff = data
        diff['stats'] = {'updated': len(data['updated']), 'added': len(data['added']), 'deleted': len(data['deleted'])}
        diff['date'] = self.created_date
        return diff

    def get_absolute_url(self):
        return reverse('sourceupdate', args=[str(self.id)])


class TransfoType(Enum):
    @classmethod
    def get_choices(cls, attr_=None):
        return [(attr.value, attr.name.replace('_', ' ').title()) for attr in cls if attr_ is None or attr_ == attr]

    @classmethod
    def get_choices_name(cls, attr_=None):
        return [attr.name.replace('_', ' ').title() for attr in cls if attr_ is None or attr_ == attr]

    @classmethod
    def get_choices_value(cls, attr_=None):
        return [attr.value for attr in cls if attr_ is None or attr_ == attr]


class Transformation(models.Model):
    @unique
    class Type(TransfoType):
        ACTION = 'action'
        LATERAL = 'lateral'
        TARGET = 'target'
        # cannot be removed: used by 0056_auto_20180223_0823.py
        SUPPRESSED = 'suppressed'

    @unique
    class ActionTransfoType(TransfoType):
        DROP = 'drop'
        REJECT = 'reject'
        FILESTORE = 'filestore'
        NONE = 'none'
        BYPASS = 'bypass'
        CATEGORY_DEFAULT = 'category'
        RULESET_DEFAULT = 'ruleset'

    @unique
    class LateralTransfoType(TransfoType):
        AUTO = 'auto'
        YES = 'yes'
        NO = 'no'
        CATEGORY_DEFAULT = 'category'
        RULESET_DEFAULT = 'ruleset'

    @unique
    class TargetTransfoType(TransfoType):
        SOURCE = 'src'
        DESTINATION = 'dst'
        AUTO = 'auto'
        NONE = 'none'
        CATEGORY_DEFAULT = 'category'
        RULESET_DEFAULT = 'ruleset'

    # cannot be removed: used by 0056_auto_20180223_0823.py
    @unique
    class SuppressTransforType(TransfoType):
        SUPPRESSED = 'suppressed'

    class Meta:
        abstract = True

    # Keys
    ACTION = Type.ACTION
    LATERAL = Type.LATERAL
    TARGET = Type.TARGET
    # cannot be removed: used by 0056_auto_20180223_0823.py
    SUPPRESSED = Type.SUPPRESSED

    # cannot be removed: used by 0056_auto_20180223_0823.py
    S_SUPPRESSED = SuppressTransforType.SUPPRESSED

    # Action values
    A_DROP = ActionTransfoType.DROP
    A_REJECT = ActionTransfoType.REJECT
    A_FILESTORE = ActionTransfoType.FILESTORE
    A_NONE = ActionTransfoType.NONE
    A_BYPASS = ActionTransfoType.BYPASS
    A_CAT_DEFAULT = ActionTransfoType.CATEGORY_DEFAULT
    A_RULESET_DEFAULT = ActionTransfoType.RULESET_DEFAULT

    # Lateral values
    L_AUTO = LateralTransfoType.AUTO
    L_YES = LateralTransfoType.YES
    L_NO = LateralTransfoType.NO
    L_CAT_DEFAULT = LateralTransfoType.CATEGORY_DEFAULT
    L_RULESET_DEFAULT = LateralTransfoType.RULESET_DEFAULT

    # Target transformations
    T_SOURCE = TargetTransfoType.SOURCE
    T_DESTINATION = TargetTransfoType.DESTINATION
    T_AUTO = TargetTransfoType.AUTO
    T_NONE = TargetTransfoType.NONE
    T_CAT_DEFAULT = TargetTransfoType.CATEGORY_DEFAULT
    T_RULESET_DEFAULT = TargetTransfoType.RULESET_DEFAULT

    AVAILABLE_MODEL_TRANSFO = {
        ACTION.value: (A_DROP.value, A_REJECT.value, A_FILESTORE.value, A_BYPASS.value, A_NONE.value,),
        LATERAL.value: (L_AUTO.value, L_YES.value, L_NO.value,),
        TARGET.value: (T_SOURCE.value, T_DESTINATION.value, T_AUTO.value, T_NONE.value,)
    }

    # Fields
    key = models.CharField(max_length=15, choices=Type.get_choices(), default=Type.ACTION.value)
    value = models.CharField(max_length=15, default=ActionTransfoType.NONE.value)


class Transformable:
    def get_transformation(self, ruleset, key):
        raise NotImplementedError()

    def is_transformed(self, ruleset, key=Transformation.ACTION, value=Transformation.A_DROP):
        raise NotImplementedError()

    def _set_target(self, rule, target="dest_ip"):
        target = ' target:%s;)' % target
        rule.raw = re.sub(r"\)$", "%s" % (target), rule.raw) if target not in rule.raw else rule.raw

    def _test_scan_rules(self, rule_ids):
        for option in rule_ids.options:
            if option['name'] == 'flags':
                if option['value'] == 'S,12':
                    return True
                return False
        return False

    def _apply_target_trans(self, rule_ids):
        terms = re.split(r' +', rule_ids.format())
        src = terms[2]
        dst = terms[5]

        if self._test_scan_rules(rule_ids):
            self._set_target(rule_ids, target="dest_ip")
        # external net always seen as bad guy on attack if not OUTBOUND
        elif src == "$EXTERNAL_NET":
            self._set_target(rule_ids, target="dest_ip")

        # external net always seen as bad guy on attack
        elif dst == "$EXTERNAL_NET":
            self._set_target(rule_ids, target="src_ip")

        # any or IP address list on one side and a variable on other side implies variable is our asset so target
        elif (src == "any" or src.startswith("[")) and dst.startswith("$"):
            self._set_target(rule_ids, target="dest_ip")

        # any or IP address list on one side and a variable on other side implies variable is our asset so target
        elif src.startswith("$") and (dst == "any" or dst.startswith("[")):
            self._set_target(rule_ids, target="src_ip")

        elif rule_ids.sid in [2017060, 2023070, 2023071, 2023549, 2024297, 2023548, 2024435, 2023149]:
            self._set_target(rule_ids, target="dest_ip")

        elif rule_ids.sid in []:
            self._set_target(rule_ids, target="src_ip")

    def apply_lateral_target_transfo(self, content, key=Transformation.LATERAL, value=Transformation.L_YES):
        try:
            rule_ids = rule_idstools.parse(content)
        except:
            return content

        # Workaround: ref #674
        # Cannot transform, idstools cannot parse it
        if rule_ids is None:
            return content

        # don't work on commented rules
        if rule_ids.format().startswith("#"):
            return content

        # LATERAL + YES
        if key == Transformation.LATERAL:
            if value == Transformation.L_YES:
                rule_ids.raw = rule_ids.raw.replace("$EXTERNAL_NET", "any")
                return rule_ids.format()
            elif value == Transformation.L_AUTO:
                if rule_ids.msg.startswith("ET POLICY"):
                    return content
                for meta in rule_ids.metadata:
                    # if deployment can be internal then we can relax the constraint
                    # on EXTERNAL_NET to try to catch the lateral movement
                    if meta == "deployment Internal" or meta == "deployment Datacenter":
                        rule_ids.raw = rule_ids.raw.replace("$EXTERNAL_NET", "any")

        # TARGET + DST/SRC
        if key == Transformation.TARGET:
            if value == Transformation.T_SOURCE:
                rule_ids.raw = re.sub(r' target:\w*;', '', rule_ids.raw)
                self._set_target(rule_ids, target='src_ip')
            elif value == Transformation.T_DESTINATION:
                rule_ids.raw = re.sub(r' target:\w*;', '', rule_ids.raw)
                self._set_target(rule_ids, target='dest_ip')
            elif value == Transformation.T_NONE:
                rule_ids.raw = re.sub(r' target:\w*;', '', rule_ids.raw)
            elif value == Transformation.T_AUTO:
                target_client = False
                for meta in rule_ids.metadata:
                    if meta.startswith("attack_target"):
                        target_client = True
                        break
                    if meta.startswith("mitre_tactic_id"):
                        target_client = True
                        break
                    if meta.startswith("affected_product"):
                        target_client = True
                        break

                # not satisfactory but doing the best we can not too miss something like
                # a successful bruteforce
                if rule_ids.classtype == "attempted-recon":
                    target_client = True
                if rule_ids.classtype == "not-suspicious":
                    target_client = False
                if target_client is True and 'target' not in rule_ids:
                    self._apply_target_trans(rule_ids)

        return rule_ids.format()


class Cache:
    TRANSFORMATIONS = {}

    def __init__(self):
        pass

    @classmethod
    def enable_cache(cls):
        if cls.TRANSFORMATIONS == {}:
            # Actions
            ACTION = Transformation.ACTION
            A_NONE = Transformation.A_NONE
            A_FILESTORE = Transformation.A_FILESTORE
            A_DROP = Transformation.A_DROP
            A_REJECT = Transformation.A_REJECT
            A_BYPASS = Transformation.A_BYPASS

            # Lateral
            LATERAL = Transformation.LATERAL
            L_AUTO = Transformation.L_AUTO
            L_YES = Transformation.L_YES
            L_NO = Transformation.L_NO

            # Target
            TARGET = Transformation.TARGET
            T_AUTO = Transformation.T_AUTO
            T_SOURCE = Transformation.T_SOURCE
            T_DST = Transformation.T_DESTINATION
            T_NONE = Transformation.T_NONE

            rule_str = Rule.__name__.lower()
            category_str = Category.__name__.lower()
            ruleset_str = Ruleset.__name__.lower()

            cls.TRANSFORMATIONS = {
                ACTION: {
                    rule_str: {
                        A_DROP: None, A_REJECT: None, A_FILESTORE: None, A_NONE: None, A_BYPASS: None,
                    },
                    category_str: {
                        A_DROP: None, A_REJECT: None, A_FILESTORE: None, A_NONE: None, A_BYPASS: None,
                    },
                    ruleset_str: {
                        A_DROP: None, A_REJECT: None, A_FILESTORE: None, A_BYPASS: None,
                    }
                },
                LATERAL: {
                    rule_str: {
                        L_AUTO: None, L_YES: None, L_NO: None,
                    },
                    category_str: {
                        L_AUTO: None, L_YES: None, L_NO: None,
                    },
                    ruleset_str: {
                        L_AUTO: None, L_YES: None,
                    }
                },
                TARGET: {
                    rule_str: {
                        T_AUTO: None, T_SOURCE: None, T_DST: None, T_NONE: None,
                    },
                    category_str: {
                        T_AUTO: None, T_SOURCE: None, T_DST: None, T_NONE: None,
                    },
                    ruleset_str: {
                        T_AUTO: None, T_SOURCE: None, T_DST: None,
                    }
                }
            }

            # ##### Rules
            # Actions
            drop_rules = Rule.objects.filter(
                ruletransformation__key=ACTION.value,
                ruletransformation__value=A_DROP.value
            ).values_list('pk', flat=True)

            reject_rules = Rule.objects.filter(
                ruletransformation__key=ACTION.value,
                ruletransformation__value=A_REJECT.value
            ).values_list('pk', flat=True)

            filestore_rules = Rule.objects.filter(
                ruletransformation__key=ACTION.value,
                ruletransformation__value=A_FILESTORE.value
            ).values_list('pk', flat=True)

            none_rules = Rule.objects.filter(
                ruletransformation__key=ACTION.value,
                ruletransformation__value=A_NONE.value
            ).values_list('pk', flat=True)

            bypass_rules = Rule.objects.filter(
                ruletransformation__key=ACTION.value,
                ruletransformation__value=A_BYPASS.value
            ).values_list('pk', flat=True)

            # Lateral
            rule_l_auto = Rule.objects.filter(
                ruletransformation__key=LATERAL.value,
                ruletransformation__value=L_AUTO.value
            ).values_list('pk', flat=True)

            rule_l_yes = Rule.objects.filter(
                ruletransformation__key=LATERAL.value,
                ruletransformation__value=L_YES.value
            ).values_list('pk', flat=True)

            rule_l_no = Rule.objects.filter(
                ruletransformation__key=LATERAL.value,
                ruletransformation__value=L_NO.value
            ).values_list('pk', flat=True)

            # Target
            rule_t_auto = Rule.objects.filter(
                ruletransformation__key=TARGET.value,
                ruletransformation__value=T_AUTO.value
            ).values_list('pk', flat=True)

            rule_t_src = Rule.objects.filter(
                ruletransformation__key=TARGET.value,
                ruletransformation__value=T_SOURCE.value
            ).values_list('pk', flat=True)

            rule_t_dst = Rule.objects.filter(
                ruletransformation__key=TARGET.value,
                ruletransformation__value=T_DST.value
            ).values_list('pk', flat=True)

            rule_t_none = Rule.objects.filter(
                ruletransformation__key=TARGET.value,
                ruletransformation__value=T_NONE.value
            ).values_list('pk', flat=True)

            # #### Categories
            # Actions
            drop_cats = Category.objects.filter(
                categorytransformation__key=ACTION.value,
                categorytransformation__value=A_DROP.value
            ).values_list('pk', flat=True)

            reject_cats = Category.objects.filter(
                categorytransformation__key=ACTION.value,
                categorytransformation__value=A_REJECT.value
            ).values_list('pk', flat=True)

            filestore_cats = Category.objects.filter(
                categorytransformation__key=ACTION.value,
                categorytransformation__value=A_FILESTORE.value
            ).values_list('pk', flat=True)

            none_cats = Category.objects.filter(
                categorytransformation__key=ACTION.value,
                categorytransformation__value=A_NONE.value
            ).values_list('pk', flat=True)

            bypass_cats = Category.objects.filter(
                categorytransformation__key=ACTION.value,
                categorytransformation__value=A_BYPASS.value
            ).values_list('pk', flat=True)

            # Lateral
            cat_l_auto = Category.objects.filter(
                categorytransformation__key=LATERAL.value,
                categorytransformation__value=L_AUTO.value
            ).values_list('pk', flat=True)

            cat_l_yes = Category.objects.filter(
                categorytransformation__key=LATERAL.value,
                categorytransformation__value=L_YES.value
            ).values_list('pk', flat=True)

            cat_l_no = Category.objects.filter(
                categorytransformation__key=LATERAL.value,
                categorytransformation__value=L_NO.value
            ).values_list('pk', flat=True)

            # Target
            cat_t_auto = Category.objects.filter(
                categorytransformation__key=TARGET.value,
                categorytransformation__value=T_AUTO.value
            ).values_list('pk', flat=True)

            cat_t_src = Category.objects.filter(
                categorytransformation__key=TARGET.value,
                categorytransformation__value=T_SOURCE.value
            ).values_list('pk', flat=True)

            cat_t_dst = Category.objects.filter(
                categorytransformation__key=TARGET.value,
                categorytransformation__value=T_DST.value
            ).values_list('pk', flat=True)

            cat_t_none = Category.objects.filter(
                categorytransformation__key=TARGET.value,
                categorytransformation__value=T_NONE.value
            ).values_list('pk', flat=True)

            # #### Rulesets
            # Actions
            drop_rulesets = Ruleset.objects.filter(
                rulesettransformation__key=ACTION.value,
                rulesettransformation__value=A_DROP.value
            ).values_list('pk', flat=True)

            reject_rulesets = Ruleset.objects.filter(
                rulesettransformation__key=ACTION.value,
                rulesettransformation__value=A_REJECT.value
            ).values_list('pk', flat=True)

            filestore_rulesets = Ruleset.objects.filter(
                rulesettransformation__key=ACTION.value,
                rulesettransformation__value=A_FILESTORE.value
            ).values_list('pk', flat=True)

            bypass_rulesets = Ruleset.objects.filter(
                rulesettransformation__key=ACTION.value,
                rulesettransformation__value=A_BYPASS.value
            ).values_list('pk', flat=True)

            # Lateral
            ruleset_l_auto = Ruleset.objects.filter(
                rulesettransformation__key=LATERAL.value,
                rulesettransformation__value=L_AUTO.value
            ).values_list('pk', flat=True)

            ruleset_l_yes = Ruleset.objects.filter(
                rulesettransformation__key=LATERAL.value,
                rulesettransformation__value=L_YES.value
            ).values_list('pk', flat=True)

            # Target
            ruleset_t_auto = Ruleset.objects.filter(
                rulesettransformation__key=TARGET.value,
                rulesettransformation__value=T_AUTO.value
            ).values_list('pk', flat=True)

            ruleset_t_src = Ruleset.objects.filter(
                rulesettransformation__key=TARGET.value,
                rulesettransformation__value=T_SOURCE.value
            ).values_list('pk', flat=True)

            ruleset_t_dst = Ruleset.objects.filter(
                rulesettransformation__key=TARGET.value,
                rulesettransformation__value=T_DST.value
            ).values_list('pk', flat=True)

            # Set rules action cache
            cls.TRANSFORMATIONS[ACTION][rule_str][A_DROP] = set(drop_rules)
            cls.TRANSFORMATIONS[ACTION][rule_str][A_REJECT] = set(reject_rules)
            cls.TRANSFORMATIONS[ACTION][rule_str][A_FILESTORE] = set(filestore_rules)
            cls.TRANSFORMATIONS[ACTION][rule_str][A_NONE] = set(none_rules)
            cls.TRANSFORMATIONS[ACTION][rule_str][A_BYPASS] = set(bypass_rules)

            cls.TRANSFORMATIONS[LATERAL][rule_str][L_AUTO] = set(rule_l_auto)
            cls.TRANSFORMATIONS[LATERAL][rule_str][L_YES] = set(rule_l_yes)
            cls.TRANSFORMATIONS[LATERAL][rule_str][L_NO] = set(rule_l_no)

            cls.TRANSFORMATIONS[TARGET][rule_str][T_AUTO] = set(rule_t_auto)
            cls.TRANSFORMATIONS[TARGET][rule_str][T_SOURCE] = set(rule_t_src)
            cls.TRANSFORMATIONS[TARGET][rule_str][T_DST] = set(rule_t_dst)
            cls.TRANSFORMATIONS[TARGET][rule_str][T_NONE] = set(rule_t_none)

            # set categories action cache
            cls.TRANSFORMATIONS[ACTION][category_str][A_DROP] = set(drop_cats)
            cls.TRANSFORMATIONS[ACTION][category_str][A_REJECT] = set(reject_cats)
            cls.TRANSFORMATIONS[ACTION][category_str][A_FILESTORE] = set(filestore_cats)
            cls.TRANSFORMATIONS[ACTION][category_str][A_BYPASS] = set(bypass_cats)
            cls.TRANSFORMATIONS[ACTION][category_str][A_NONE] = set(none_cats)

            cls.TRANSFORMATIONS[LATERAL][category_str][L_AUTO] = set(cat_l_auto)
            cls.TRANSFORMATIONS[LATERAL][category_str][L_YES] = set(cat_l_yes)
            cls.TRANSFORMATIONS[LATERAL][category_str][L_NO] = set(cat_l_no)

            cls.TRANSFORMATIONS[TARGET][category_str][T_AUTO] = set(cat_t_auto)
            cls.TRANSFORMATIONS[TARGET][category_str][T_SOURCE] = set(cat_t_src)
            cls.TRANSFORMATIONS[TARGET][category_str][T_DST] = set(cat_t_dst)
            cls.TRANSFORMATIONS[TARGET][category_str][T_NONE] = set(cat_t_none)

            # set rulesets action cache
            cls.TRANSFORMATIONS[ACTION][ruleset_str][A_DROP] = set(drop_rulesets)
            cls.TRANSFORMATIONS[ACTION][ruleset_str][A_REJECT] = set(reject_rulesets)
            cls.TRANSFORMATIONS[ACTION][ruleset_str][A_FILESTORE] = set(filestore_rulesets)
            cls.TRANSFORMATIONS[ACTION][ruleset_str][A_BYPASS] = set(bypass_rulesets)

            cls.TRANSFORMATIONS[LATERAL][ruleset_str][L_AUTO] = set(ruleset_l_auto)
            cls.TRANSFORMATIONS[LATERAL][ruleset_str][L_YES] = set(ruleset_l_yes)

            cls.TRANSFORMATIONS[TARGET][ruleset_str][T_AUTO] = set(ruleset_t_auto)
            cls.TRANSFORMATIONS[TARGET][ruleset_str][T_SOURCE] = set(ruleset_t_src)
            cls.TRANSFORMATIONS[TARGET][ruleset_str][T_DST] = set(ruleset_t_dst)

        else:
            raise Exception("Rule cache has not been closed")

    @classmethod
    def disable_cache(cls):
        if cls.TRANSFORMATIONS != {}:
            del cls.TRANSFORMATIONS
            cls.TRANSFORMATIONS = {}
        else:
            raise Exception("%s cache has not been open" % cls.__name__)


class Category(models.Model, Transformable, Cache):
    name = models.CharField(max_length=100)
    filename = models.CharField(max_length=200)
    descr = models.CharField(max_length=400, blank=True)
    created_date = models.DateTimeField('date created', default=timezone.now)
    source = models.ForeignKey(Source, on_delete=models.CASCADE)

    class Meta:
        verbose_name_plural = "categories"

    def __str__(self):
        return self.name

    def __init__(self, *args, **kwargs):
        models.Model.__init__(self, *args, **kwargs)
        Cache.__init__(self)

    @staticmethod
    def get_icon():
        return 'fa-list-alt'

    def build_sigs_group(self):
        # query sigs with group set
        rules = Rule.objects.filter(group=True, category=self)
        sigs_groups = {}

        # build hash on message
        for rule in rules:
            # let's get the new IP only, will output that as text field at save time
            rule.ips_list = set()
            sigs_groups[rule.msg] = {
                'rule': rule,
                'rav': rule.ruleatversion_set.get(version=0)
            }
        return sigs_groups

    def parse_group_signature(self, group_rule, rule):
        if group_rule.group_by == 'by_src':
            ips_list = Rule.IPSREGEXP['src'].findall(rule.header)[0]
        else:
            ips_list = Rule.IPSREGEXP['dest'].findall(rule.header)[0]
        if ips_list.startswith('['):
            ips_list = ips_list[1:-1].split(',')
        else:
            ips_list = [ips_list, ]
        group_rule.ips_list.update(ips_list)
        group_rule.next_rev = rule.rev

    def add_group_signature(self, sigs_groups, line, existing_rules_hash, source, flowbits, rules_update, rules_unchanged):
        # parse the line with ids tools
        try:
            rule = rule_idstools.parse(line)
        except:
            return
        if rule is None:
            return

        # version is always at 0 here while versioning is done on stamus source only
        version = 0
        rule_base_msg = Rule.GROUPSNAMEREGEXP.findall(rule.msg)[0]
        ips_list = Rule.IPSREGEXP['src'].findall(rule.header)[0]
        track_by = 'src' if ips_list.startswith('[') else 'dst'
        content = rule.raw
        iprep_group = rule.sid

        content = content.replace(';)', '; iprep:%s,%s,>,1;)' % (track_by, iprep_group))
        # replace IP list by any
        content = re.sub(r'\[\d+.*\d+\]', r'any', content)
        # fix message
        content = re.sub(r'msg:".*";', r'msg:"%s";' % rule_base_msg, content)

        # check if we already have a signature in the group signatures
        # that match
        if rule_base_msg in sigs_groups:
            # TODO coherence check
            # add IPs to the list if revision has changed
            rav = sigs_groups[rule_base_msg]['rav']
            group_rule = sigs_groups[rule_base_msg]['rule']

            if content != rav.content:
                self.parse_group_signature(group_rule, rule)
                # Is there an existing rule to clean ? this is needed at
                # conversion of source to use iprep but we will have a different
                # message in this case (with group)
                if rule.sid in existing_rules_hash and version in existing_rules_hash[rule.sid]:
                    # the sig is already present and it is a group sid so let's declare it
                    # updated to avoid its deletion later in process. No else clause because
                    # the signature will be deleted as it is not referenced in a changed or
                    # unchanged list
                    if rule_base_msg == existing_rules_hash[rule.sid][version].rule.msg:
                        rules_update["updated"].append(existing_rules_hash[rule.sid][version].rule)
            else:
                rules_unchanged.append(group_rule)
        else:
            creation_date = timezone.now()
            state = True
            if rule.raw.startswith("#"):
                state = False

            # if we already have a signature with the SID we are probably parsing
            # a source that has just been switched to iprep. So we get the old
            # rule and we update the content to avoid loosing information.
            if rule.sid in existing_rules_hash and version in existing_rules_hash[rule.sid]:
                rav = existing_rules_hash[rule.sid][version]
                group_rule = rav.rule
                group_rule.group = True
                group_rule.msg = rule_base_msg
                rav.content = content
                rav.updated_date = creation_date
                rav.rev = rule.rev

                if rav.state != rav.commented_in_source and rav.commented_in_source == state:
                    rav.state = state
                rav.commented_in_source = not state
                rav.save()
                rules_update["updated"].append(group_rule)
            else:
                group_rule = Rule(
                    category=self,
                    sid=rule.sid,
                    group=True,
                    msg=rule_base_msg,
                )

                rav = RuleAtVersion(
                    rule=group_rule,
                    rev=rule.rev - 1,
                    version=version,
                    content=line,
                    state=state,
                    commented_in_source=not state,
                    imported_date=creation_date,
                    updated_date=creation_date
                )

                rav.parse_metadata()
                rav.parse_flowbits(source, flowbits, addition=True)
                rules_update["updated"].append(group_rule)
                rules_update['ravs'].append(rav)
            if track_by == 'src':
                group_rule.group_by = 'by_src'
            else:
                group_rule.group_by = 'by_dest'
            group_rule.ips_list = set()
            self.parse_group_signature(group_rule, rule)
            sigs_groups[group_rule.msg] = {
                'rule': group_rule,
                'rav': rav
            }

    def get_rules(self, source, version=0, filename=None, existing_rules_hash=None):
        # parse file
        # return an object with updates
        getsid = re.compile(r"sid *: *(\d+)")
        getrev = re.compile(r"rev *: *(\d+)")
        getmsg = re.compile(r"msg *: *\"(.*?)\"")
        source_git_dir = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.source.pk))

        if filename is None:
            filename = self.filename

        rules_update = {"added": [], "deleted": [], "updated": [], 'ravs': []}
        flowbits = {'added': {'flowbit': [], 'through_set': [], 'through_isset': []}}
        rules_unchanged = []

        if existing_rules_hash is None:
            existing_rules_hash = {}
            for rule in Rule.objects.all().prefetch_related('category'):
                if rule.sid not in existing_rules_hash:
                    existing_rules_hash[rule.sid] = {}

                for rav in rule.ruleatversion_set.all():
                    existing_rules_hash[rule.sid][rav.version] = rav

        rules_list = []
        for rule in Rule.objects.filter(category=self):
            rules_list.append(rule)

        for key in ('flowbits', 'hostbits', 'xbits'):
            flowbits[key] = {}
            for flowb in Flowbit.objects.filter(source=source, type=key):
                flowbits[key][flowb.name] = flowb

        creation_date = timezone.now()

        rules_groups = {}
        if source.use_iprep:
            rules_groups = self.build_sigs_group()

        with open(os.path.join(source_git_dir, filename)) as rfile:
            with transaction.atomic():
                duplicate_source = set()
                duplicate_sids = set()

                for line in rfile.readlines():
                    state = True
                    if line.startswith('#'):
                        # check if it is a commented signature
                        if "->" in line and "sid" in line and ")" in line:
                            line = line.lstrip("# ")
                            state = False
                        else:
                            continue
                    match = getsid.search(line)
                    if not match:
                        continue
                    sid_str = match.groups()[0]
                    match = getrev.search(line)
                    if match:
                        rev = int(match.groups()[0])
                    else:
                        rev = None
                    match = getmsg.search(line)
                    if not match:
                        msg = ""
                    else:
                        msg = match.groups()[0]
                        # length of message could exceed 1000 so truncate
                        if len(msg) > 1000:
                            msg = msg[0:999]

                    if source.use_iprep and Rule.GROUPSNAMEREGEXP.match(msg):
                        self.add_group_signature(rules_groups, line, existing_rules_hash, source, flowbits, rules_update, rules_unchanged)
                    else:
                        sid = int(sid_str)
                        if sid in existing_rules_hash and version in existing_rules_hash[sid]:
                            # FIXME update references if needed
                            rav = existing_rules_hash[sid][version]
                            rule = rav.rule

                            if rule.category.source != source:
                                source_name = rule.category.source.name
                                duplicate_source.add(source_name)
                                duplicate_sids.add(sid_str)
                                if len(duplicate_sids) == 20:
                                    break
                                continue

                            if rav.content != line or rule.group is True or (rav.state != rav.commented_in_source and rav.commented_in_source == state):
                                rav.content = line

                                if rav.state != rav.commented_in_source and rav.commented_in_source == state:
                                    rav.state = state
                                rav.commented_in_source = not state

                                rav.rev = 0 if rev is None else rev
                                rav.parse_metadata()
                                rav.parse_flowbits(source, flowbits)
                                rav.save()

                                rule.updated_date = creation_date
                                if rule.category != self:
                                    rule.category = self

                                if rule.msg != msg:
                                    rule.msg = msg

                                rule.save()
                                rules_update["updated"].append(rule)

                            else:
                                rules_unchanged.append(rule)
                        else:
                            if rev is None:
                                rev = 0

                            if sid in existing_rules_hash:
                                rule = list(existing_rules_hash[sid].values())[0].rule
                                rules_update["updated"].append(rule)
                            else:
                                rule = Rule(
                                    category=self,
                                    sid=sid,
                                    msg=msg,
                                )
                                existing_rules_hash[rule.sid] = {}

                                try:
                                    rule.full_clean()
                                except ValidationError as e:
                                    err = {'sid_': rule.sid}
                                    err.update(e.message_dict)
                                    raise ValidationError(err)

                                rules_update["added"].append(rule)

                            rav = RuleAtVersion(
                                rule=rule,
                                rev=rev,
                                version=version,
                                content=line,
                                state=state,
                                commented_in_source=not state,
                                imported_date=creation_date,
                                updated_date=creation_date
                            )

                            rav.parse_metadata()
                            rav.parse_flowbits(source, flowbits, addition=True)
                            rules_update["ravs"].append(rav)
                            existing_rules_hash[rule.sid][rav.version] = rav

                if len(duplicate_sids):
                    sids = sorted(duplicate_sids)
                    if len(sids) == 20:
                        sids += '...'
                    sids = ', '.join(sids)
                    source_name = ', '.join(sorted(duplicate_source))

                    raise ValidationError('The source contains conflicting SID (%s) with other sources (%s)' % (sids, source_name))

                if len(rules_update["added"]):
                    Rule.objects.bulk_create(rules_update["added"])

                if len(rules_update['ravs']):
                    RuleAtVersion.objects.bulk_create(rules_update['ravs'])

                if len(rules_groups):
                    for val in rules_groups.values():
                        # If IP list is empty it will be deleted because it has not
                        # been put in a changed or unchanged list. So we just care
                        # about saving the rule.
                        rav = val['rav']
                        rule = val['rule']

                        if len(rule.ips_list) > 0:
                            rule.group_ips_list = ",".join(rule.ips_list)
                            rule.save()
                            rav.rev = rule.next_rev
                            rav.save()

                if len(flowbits["added"]["flowbit"]):
                    Flowbit.objects.bulk_create(flowbits["added"]["flowbit"])
                if len(flowbits["added"]["through_set"]):
                    Flowbit.set.through.objects.bulk_create(flowbits["added"]["through_set"])
                if len(flowbits["added"]["through_isset"]):
                    Flowbit.isset.through.objects.bulk_create(flowbits["added"]["through_isset"])
                rules_update["deleted"] = list(
                    set(rules_list) -
                    set(rules_update["added"]).union(set(rules_update["updated"])) -
                    set(rules_unchanged)
                )
                source.aggregate_update(rules_update)

    def get_absolute_url(self):
        return reverse('category', args=[str(self.id)])

    def enable(self, ruleset, request=None, comment=None):
        ruleset.categories.add(self)
        ruleset.needs_test()
        ruleset.save()
        if request:
            UserAction.create(
                action_type='enable_category',
                comment=comment,
                request=request,
                category=self,
                ruleset=ruleset
            )

    def disable(self, ruleset, request=None, comment=None):
        ruleset.categories.remove(self)
        ruleset.needs_test()
        ruleset.save()
        if request:
            UserAction.create(
                action_type='disable_category',
                comment=comment,
                request=request,
                category=self,
                ruleset=ruleset
            )

    def is_transformed(self, ruleset, key=Transformation.ACTION, value=Transformation.A_DROP):
        if Category.TRANSFORMATIONS == {}:
            return (self.pk in ruleset.get_transformed_categories(key=key, value=value).values_list('pk', flat=True))

        category_str = Category.__name__.lower()
        return (self.pk in Category.TRANSFORMATIONS[key][category_str][value])

    def suppress_transformation(self, ruleset, key):
        CategoryTransformation.objects.filter(
            ruleset=ruleset,
            category_transformation=self,
            key=key.value
        ).delete()

    def toggle_transformation(self, ruleset, key=Transformation.ACTION, value=Transformation.A_DROP):
        if self.is_transformed(ruleset, key=key, value=value):
            CategoryTransformation.objects.filter(
                ruleset=ruleset,
                category_transformation=self,
                key=key.value
            ).delete()
        else:
            c = CategoryTransformation(
                ruleset=ruleset,
                category_transformation=self,
                key=key.value,
                value=value.value
            )
            c.save()
        ruleset.needs_test()

    def get_transformation(self, ruleset, key=Transformation.ACTION, override=False):
        TYPE = None

        if key == Transformation.ACTION:
            TYPE = Transformation.ActionTransfoType
        elif key == Transformation.LATERAL:
            TYPE = Transformation.LateralTransfoType
        elif key == Transformation.TARGET:
            TYPE = Transformation.TargetTransfoType
        else:
            raise Exception("Key '%s' is unknown" % key)

        if Category.TRANSFORMATIONS == {}:
            ct = CategoryTransformation.objects.filter(
                key=key.value,
                ruleset=ruleset,
                category_transformation=self
            )
            if len(ct) > 0:
                return TYPE(ct[0].value)

            if override:
                rt = RulesetTransformation.objects.filter(
                    key=key.value,
                    ruleset_transformation=ruleset
                )
                if len(rt) > 0:
                    return TYPE(rt[0].value)

        else:
            category_str = Category.__name__.lower()
            ruleset_str = Ruleset.__name__.lower()

            for trans, tsets in Category.TRANSFORMATIONS[key][category_str].items():
                if self.pk in tsets:  # DROP / REJECT / FILESTORE / NONE
                    return trans

            if override:
                for trans, tsets in Rule.TRANSFORMATIONS[key][ruleset_str].items():
                    if self.category.pk in tsets:
                        return trans

        return None

    @staticmethod
    def get_transformation_choices(key=Transformation.ACTION):
        # Keys
        ACTION = Transformation.ACTION
        LATERAL = Transformation.LATERAL
        TARGET = Transformation.TARGET

        allowed_choices = []

        if key == ACTION:
            all_choices_set = set(Transformation.ActionTransfoType.get_choices())
            allowed_choices = list(all_choices_set.intersection(set(settings.RULESET_TRANSFORMATIONS)))

            A_BYPASS = Transformation.A_BYPASS
            A_RULESET_DEFAULT = Transformation.A_RULESET_DEFAULT
            A_NONE = Transformation.A_NONE

            # TODO: move me in settings.RULESET_TRANSFORMATIONS
            allowed_choices.append((A_BYPASS.value, A_BYPASS.name.title()))
            allowed_choices.append((A_RULESET_DEFAULT.value, A_RULESET_DEFAULT.name.replace('_', ' ').title()))
            allowed_choices.append((A_NONE.value, A_NONE.name.title()))

        if key == TARGET:
            CAT_DEFAULT = Transformation.T_CAT_DEFAULT
            allowed_choices = list(Transformation.TargetTransfoType.get_choices())
            allowed_choices.remove((CAT_DEFAULT.value, CAT_DEFAULT.name.replace('_', ' ').title()))

        if key == LATERAL:
            CAT_DEFAULT = Transformation.L_CAT_DEFAULT
            allowed_choices = list(Transformation.LateralTransfoType.get_choices())
            allowed_choices.remove((CAT_DEFAULT.value, CAT_DEFAULT.name.replace('_', ' ').title()))

        return tuple(sorted(allowed_choices))


class Rule(models.Model, Transformable, Cache):
    GROUP_BY_CHOICES = (('by_src', 'by_src'), ('by_dst', 'by_dst'))
    sid = models.IntegerField(primary_key=True)
    category = models.ForeignKey(Category, on_delete=models.CASCADE)
    msg = models.CharField(max_length=1000)
    group = models.BooleanField(default=False)
    group_by = models.CharField(max_length=10, choices=GROUP_BY_CHOICES, default='by_src')
    group_ips_list = models.TextField(blank=True, null=True)  # store one IP per line
    created = models.DateField(blank=True, null=True)
    updated = models.DateField(blank=True, null=True)

    hits = 0

    IPSREGEXP = {'src': re.compile(r'^\S+ +\S+ (.*) +\S+ +\->'), 'dest': re.compile(r'\-> (.*) +\S+$')}

    GROUPSNAMEREGEXP = re.compile(r'^(.*) +group +\d+$')

    def __str__(self):
        return str(self.sid) + ":" + self.msg

    def __init__(self, *args, **kwargs):
        models.Model.__init__(self, *args, **kwargs)
        Cache.__init__(self)

    def can_drop(self):
        '''
        True if one of the rule at version is True
        '''
        for rav in self.ruleatversion_set.all():
            if rav.can_drop():
                return True
        return False

    def can_filestore(self):
        '''
        True if one of the rule at version is True
        '''
        for rav in self.ruleatversion_set.all():
            if rav.can_filestore():
                return True
        return False

    def can_lateral(self):
        '''
        True if one of the rule at version is True
        '''
        for rav in self.ruleatversion_set.all():
            if rav.can_lateral():
                return True
        return False

    def can_target(self):
        '''
        True if one of the rule at version is True
        '''
        for rav in self.ruleatversion_set.all():
            if rav.can_target():
                return True
        return False

    def are_ravs_synched(self):
        nb = 0
        max = self.ruleatversion_set.count()
        for rav in self.ruleatversion_set.all():
            if not rav.state:
                nb += 1
        return nb == 0 or nb == max

    def are_ravs_all_commented(self):
        nb = 0
        max = self.ruleatversion_set.count()
        for rav in self.ruleatversion_set.all():
            if rav.commented_in_source:
                nb += 1
        return nb == max

    @staticmethod
    def get_icon():
        return 'pficon-security'

    def get_absolute_url(self):
        return reverse('rule', args=[str(self.sid)])

    def get_actions(self, user):
        history = UserAction.objects.filter(
            user_action_objects__content_type=ContentType.objects.get_for_model(Rule),
            user_action_objects__object_id=self.pk
        ).order_by('-date')

        res = []
        for item in history:
            res.append({
                'description': item.generate_description(user),
                'comment': item.comment,
                'title': item.get_title(),
                'date': item.date,
                'icons': item.get_icons(),
                'client_ip': item.client_ip
            })
        return res

    def get_comments(self):
        return UserAction.objects.filter(
            action_type__in=['comment_rule', 'transform_rule', 'enable_rule', 'suppress_rule', 'disable_rule', 'delete_suppress_rule'],
            user_action_objects__content_type=ContentType.objects.get_for_model(Rule),
            user_action_objects__object_id=self.pk
        ).order_by('-date')

    def get_dependant_rules_at_version(self, ruleset):
        ravs = []
        for rav in self.ruleatversion_set.all():
            ravs.append(rav)
            ravs.extend(rav.get_dependant_rules_at_version(ruleset))
        return ravs

    def enable(self, ruleset, request=None, comment=None):
        ruleset.enable_rules_at_version(self.get_dependant_rules_at_version(ruleset))
        if request:
            UserAction.create(
                action_type='enable_rule',
                comment=comment,
                request=request,
                rule=self,
                ruleset=ruleset
            )
        return

    def disable(self, ruleset, request=None, comment=None):
        ruleset.disable_rules_at_version(self.get_dependant_rules_at_version(ruleset))
        if request:
            UserAction.create(
                action_type='disable_rule',
                comment=comment,
                request=request,
                rule=self,
                ruleset=ruleset
            )
        return

    def test(self, ruleset):
        try:
            self.enable_cache()
            test = ruleset.test_rule_buffer(self.generate_content(ruleset), single=True)
        except:
            return False
        finally:
            self.disable_cache()
        return test

    def toggle_availability(self, version=None):
        self.category.source.needs_test()
        ravs = self.ruleatversion_set.filter(version=version) if version is not None else self.ruleatversion_set.all()

        for rav in ravs:
            rav.toggle_availability()

    def apply_transformation(self, content, key=Transformation.ACTION, value=None):

        if key == Transformation.ACTION:
            if value == Transformation.A_REJECT:
                content = re.sub(r"^ *\S+", "reject", content)
            elif value == Transformation.A_DROP:
                content = re.sub(r"^ *\S+", "drop", content)
            elif value == Transformation.A_FILESTORE:
                content = re.sub(r"; *\)", "; filestore;)", content)
            elif value == Transformation.A_BYPASS:
                if 'noalert' in content:
                    content = re.sub(r"; noalert;", "; noalert; bypass;", content)
                else:
                    content = re.sub(r"; *\)$", "; noalert; bypass;)", content)
                content = re.sub(r"^ *\S+", "pass", content)

        elif key == Transformation.LATERAL or key == Transformation.TARGET:
            content = self.apply_lateral_target_transfo(content, key, value)

        return content

    def is_transformed(self, ruleset, key=Transformation.ACTION, value=Transformation.A_DROP):
        if Rule.TRANSFORMATIONS == {}:
            return (self in ruleset.get_transformed_rules(key=key, value=value).values_list('pk', flat=True))

        rule_str = Rule.__name__.lower()
        return (self.pk in Rule.TRANSFORMATIONS[key][rule_str][value])

    def get_transformation(self, ruleset, key=Transformation.ACTION, override=False):
        TYPE = None

        if key == Transformation.ACTION:
            TYPE = Transformation.ActionTransfoType
        elif key == Transformation.LATERAL:
            TYPE = Transformation.LateralTransfoType
        elif key == Transformation.TARGET:
            TYPE = Transformation.TargetTransfoType
        else:
            raise Exception("Key '%s' is unknown" % key)

        if Rule.TRANSFORMATIONS == {}:
            rt = RuleTransformation.objects.filter(
                key=key.value,
                ruleset=ruleset,
                rule_transformation=self
            ).all()

            if len(rt) > 0:
                return TYPE(rt[0].value)

            if override:
                ct = CategoryTransformation.objects.filter(
                    key=key.value,
                    ruleset=ruleset,
                    category_transformation=self.category
                ).all()

                if len(ct) > 0:
                    return TYPE(ct[0].value)

                rt = RulesetTransformation.objects.filter(
                    key=key.value,
                    ruleset_transformation=ruleset
                )
                if len(rt) > 0:
                    return TYPE(rt[0].value)

        else:
            rule_str = Rule.__name__.lower()
            category_str = Category.__name__.lower()
            ruleset_str = Ruleset.__name__.lower()

            for trans, tsets in Rule.TRANSFORMATIONS[key][rule_str].items():
                if self.pk in tsets:
                    return trans

            if override:
                for trans, tsets in Rule.TRANSFORMATIONS[key][category_str].items():
                    if self.category.pk in tsets:
                        return trans

                for trans, tsets in Rule.TRANSFORMATIONS[key][ruleset_str].items():
                    if ruleset.pk in tsets:
                        return trans

        return None

    def remove_transformations(self, ruleset, key):
        RuleTransformation.objects.filter(
            ruleset=ruleset,
            rule_transformation=self,
            key=key.value
        ).delete()

        ruleset.needs_test()
        ruleset.save()

    def set_transformation(self, ruleset, key=Transformation.ACTION, value=Transformation.A_DROP):
        self.remove_transformations(ruleset, key)

        r = RuleTransformation(
            ruleset=ruleset,
            rule_transformation=self,
            key=key.value,
            value=value.value
        )
        r.save()

        ruleset.needs_test()
        ruleset.save()

    def is_untrusted(self):
        try:
            return self.untrusted
        except:
            pass
        return self.category.source.untrusted

    def generate_content(self, ruleset, version=0):
        try:
            rule_at_version = self.ruleatversion_set.get(version=version)
        except self.DoesNotExist:
            request_logger.warning('Rule %s at version %s does not exist' % (self.pk, version))
            return ''
        return rule_at_version.generate_content(ruleset)

    def get_transformation_choices(self, key=Transformation.ACTION):
        # Keys
        ACTION = Transformation.ACTION
        LATERAL = Transformation.LATERAL
        TARGET = Transformation.TARGET

        allowed_choices = []

        if key == ACTION:
            all_choices_set = set(Transformation.ActionTransfoType.get_choices())
            allowed_choices = list(all_choices_set.intersection(set(settings.RULESET_TRANSFORMATIONS)))

            A_DROP = Transformation.A_DROP
            A_FILESTORE = Transformation.A_FILESTORE
            A_REJECT = Transformation.A_REJECT
            A_BYPASS = Transformation.A_BYPASS
            A_NONE = Transformation.A_NONE
            A_CATEGORY = Transformation.A_CAT_DEFAULT

            # Remove not allowed actions
            if not self.can_drop():
                if (A_DROP.value, A_DROP.name.title()) in allowed_choices:
                    allowed_choices.remove((A_DROP.value, A_DROP.name.title()))

                if (A_REJECT.value, A_REJECT.name.title()) in allowed_choices:
                    allowed_choices.remove((A_REJECT.value, A_REJECT.name.title()))

            if not self.can_filestore():
                if (A_FILESTORE.value, A_FILESTORE.name.title()) in allowed_choices:
                    allowed_choices.remove((A_FILESTORE.value, A_FILESTORE.name.title()))

            # Test with Bypass transformation
            # TODO: move me in settings.RULESET_TRANSFORMATIONS
            allowed_choices.append((A_BYPASS.value, A_BYPASS.name.title()))

            # Add None/Category actions (Only for Rules)
            allowed_choices.append((A_CATEGORY.value, A_CATEGORY.name.replace('_', ' ').title()))
            allowed_choices.append((A_NONE.value, A_NONE.name.title()))

        elif key == TARGET:
            RULESET_DEFAULT = Transformation.T_RULESET_DEFAULT

            allowed_choices = list(Transformation.TargetTransfoType.get_choices())
            allowed_choices.remove((RULESET_DEFAULT.value, RULESET_DEFAULT.name.replace('_', ' ').title()))
            # Workaround (self.target): ref #674
            # Cannot transform, idstools cannot parse it
            # So remove this transformation from choices
            if not self.can_target():
                T_AUTO = Transformation.T_AUTO
                T_SOURCE = Transformation.T_SOURCE
                T_DEST = Transformation.T_DESTINATION

                for trans in (T_AUTO, T_SOURCE, T_DEST):
                    allowed_choices.remove((trans.value, trans.name.title()))

        elif key == LATERAL:
            RULESET_DEFAULT = Transformation.L_RULESET_DEFAULT

            allowed_choices = list(Transformation.LateralTransfoType.get_choices())
            allowed_choices.remove((RULESET_DEFAULT.value, RULESET_DEFAULT.name.replace('_', ' ').title()))

            L_YES = Transformation.L_YES
            L_AUTO = Transformation.L_AUTO

            if not self.can_lateral():
                for trans in (L_YES, L_AUTO):
                    allowed_choices.remove((trans.value, trans.name.title()))

        return tuple(allowed_choices)


def build_iprep_name(msg):
    return re.sub('[^0-9a-zA-Z]+', '_', msg.replace(' ', ''))


class RuleAtVersion(models.Model):
    rule = models.ForeignKey(Rule, on_delete=models.CASCADE)
    rev = models.IntegerField(default=0)
    version = models.IntegerField(default=0)
    content = models.CharField(max_length=10000)
    state = models.BooleanField(default=True)
    commented_in_source = models.BooleanField(default=False)

    imported_date = models.DateTimeField(default=timezone.now)
    updated_date = models.DateTimeField(default=timezone.now)
    created = models.DateField(blank=True, null=True)
    updated = models.DateField(blank=True, null=True)

    BITSREGEXP = {
        'flowbits': re.compile("flowbits *: *(isset|set),(.*?) *;"),
        'hostbits': re.compile("hostbits *: *(isset|set),(.*?) *;"),
        'xbits': re.compile("xbits *: *(isset|set),(.*?) *;"),
    }

    class Meta:
        unique_together = ('rule', 'version')

    def is_active(self, ruleset):
        return self.state and \
            self.rule.category in ruleset.categories.all() and \
            not self.is_suppressed(ruleset)

    def is_suppressed(self, ruleset):
        return SuppressedRuleAtVersion.objects.filter(ruleset=ruleset, rule_at_version=self).count() > 0

    def get_dependant_rules_at_version(self, ruleset):
        '''
        flowbit dependency:
        if we disable a rule that is the last one set a flag then we must disable all the
        dependant rules
        '''
        # get list of flowbit we are setting
        flowbits_list = Flowbit.objects.filter(set=self).prefetch_related('set', 'isset')
        dependant_ravs = []
        for flowbit in flowbits_list:
            set_count = 0
            for rav in flowbit.set.all():
                if rav == self:
                    continue
                if rav.is_active(ruleset):
                    set_count += 1
            if set_count == 0:
                dependant_ravs.extend(list(flowbit.isset.all()))
                # we need to recurse if ever we did disable in a chain of signatures
                for drav in flowbit.isset.all():
                    dependant_ravs.extend(drav.get_dependant_rules_at_version(ruleset))
        return dependant_ravs

    def toggle_availability(self):
        self.rule.category.source.needs_test()
        self.state = not self.state
        self.save()

    def match_dataset(self):
        return re.match(r'.* \(.*dataset:.*(save|state) .*;\)$', self.content)

    def match_luajit(self):
        return re.match(r'.* \(.*(luajit|lua):.*;\)$', self.content)

    def can_drop(self):
        return "noalert" not in self.content

    def can_filestore(self):
        return self.content.split(' ')[1] in ('http', 'smtp', 'smb', 'nfs', 'ftp-data')

    def can_lateral(self):
        try:
            rule_ids = rule_idstools.parse(self.content)
        except:
            return False
        # Workaround: ref #674
        # Cannot transform, idstools cannot parse it
        # So remove this transformation from choices
        if rule_ids is None or 'outbound' in rule_ids['msg'].lower():
            return False

        if '$EXTERNAL_NET' in rule_ids.raw:
            return True

        return False

    def can_target(self):
        try:
            rule_ids = rule_idstools.parse(self.content)
        except:
            return False
        return (rule_ids is not None)

    def generate_content(self, ruleset):
        content = self.content

        if self.rule.is_untrusted() and (self.match_luajit() or self.match_dataset()):
            return 'disabled as source is untrusted: %s' % content

        # explicitely set prio on transformation here
        # Action
        ACTION = Transformation.ACTION
        A_DROP = Transformation.A_DROP
        A_FILESTORE = Transformation.A_FILESTORE
        A_REJECT = Transformation.A_REJECT
        A_BYPASS = Transformation.A_BYPASS

        trans = self.rule.get_transformation(key=ACTION, ruleset=ruleset, override=True)
        if (trans in (A_DROP, A_REJECT) and self.can_drop()) or \
                (trans == A_FILESTORE and self.can_filestore()) or \
                (trans == A_BYPASS):
            content = self.rule.apply_transformation(content, key=Transformation.ACTION, value=trans)

        # Lateral
        LATERAL = Transformation.LATERAL
        L_AUTO = Transformation.L_AUTO
        L_YES = Transformation.L_YES

        trans = self.rule.get_transformation(key=LATERAL, ruleset=ruleset, override=True)
        if trans in (L_YES, L_AUTO) and self.can_lateral():
            content = self.rule.apply_transformation(content, key=Transformation.LATERAL, value=trans)

        # Target
        TARGET = Transformation.TARGET
        T_SOURCE = Transformation.T_SOURCE
        T_DESTINATION = Transformation.T_DESTINATION
        T_AUTO = Transformation.T_AUTO
        T_NONE = Transformation.T_NONE

        trans = self.rule.get_transformation(key=TARGET, ruleset=ruleset, override=True)
        if trans in (T_SOURCE, T_DESTINATION, T_AUTO, T_NONE):
            content = self.rule.apply_transformation(content, key=Transformation.TARGET, value=trans)

        return content

    def parse_flowbits(self, source, flowbits, addition=False):
        for ftype in self.BITSREGEXP:
            match = self.BITSREGEXP[ftype].findall(self.content)
            if match:
                rule_flowbits = []
                for flowinst in match:
                    # avoid flowbit duplicate
                    if not flowinst[1] in rule_flowbits:
                        rule_flowbits.append(flowinst[1])
                    else:
                        continue
                    # create Flowbit if needed
                    if not flowinst[1] in list(flowbits[ftype].keys()):
                        elt = Flowbit(
                            type=ftype,
                            name=flowinst[1],
                            source=source
                        )
                        flowbits[ftype][flowinst[1]] = elt
                        flowbits['added']['flowbit'].append(elt)
                    else:
                        elt = flowbits[ftype][flowinst[1]]

                    if flowinst[0] == "isset":
                        if addition or not self.checker.filter(isset=self):
                            through_elt = Flowbit.isset.through(flowbit=elt, rule_at_version=self)
                            flowbits['added']['through_isset'].append(through_elt)
                    elif flowinst[0] == "set":
                        if addition or not self.setter.filter(set=self):
                            through_elt = Flowbit.set.through(flowbit=elt, rule_at_version=self)
                            flowbits['added']['through_set'].append(through_elt)

    def parse_metadata_time(self, sfield):
        sdate = sfield.split(' ')[1]
        if sdate:
            de = sdate.split('_')
            try:
                return datetime_date(int(de[0]), int(de[1]), int(de[2]))
            except ValueError:
                # Catches conversion to int failure, in case the date is 'unknown'
                pass

        return None

    def parse_metadata(self):
        try:
            rule_ids = rule_idstools.parse(self.content)
        except:
            return
        if rule_ids is None:
            return
        for meta in rule_ids.metadata:
            if meta.startswith('created_at '):
                self.created = self.parse_metadata_time(meta)
            if meta.startswith('updated_at '):
                self.updated = self.parse_metadata_time(meta)

        if self.rule.created is None or self.rule.created > self.created:
            self.rule.created = self.created

        if self.rule.updated is None or self.rule.updated < self.updated:
            self.rule.updated = self.updated


class Flowbit(models.Model):
    FLOWBIT_TYPE = (('flowbits', 'Flowbits'), ('hostbits', 'Hostbits'), ('xbits', 'Xbits'))
    type = models.CharField(max_length=12, choices=FLOWBIT_TYPE)
    name = models.CharField(max_length=100)
    set = models.ManyToManyField(RuleAtVersion, related_name='setter', through='FlowbitSetRuleAtVersion')
    isset = models.ManyToManyField(RuleAtVersion, related_name='checker', through='FlowbitISSetRuleAtVersion')
    enable = models.BooleanField(default=True)
    source = models.ForeignKey(Source, on_delete=models.CASCADE)


class FlowbitSetRuleAtVersion(models.Model):
    '''
    Intermediate table between Flowbits.set and Rule (pk)
    '''
    flowbit = models.ForeignKey(Flowbit, on_delete=models.CASCADE)
    rule_at_version = models.ForeignKey(RuleAtVersion, on_delete=models.CASCADE)


class FlowbitISSetRuleAtVersion(models.Model):
    '''
    Intermediate table between Flowbits.isset and Rule (pk)
    '''
    flowbit = models.ForeignKey(Flowbit, on_delete=models.CASCADE)
    rule_at_version = models.ForeignKey(RuleAtVersion, on_delete=models.CASCADE)


# we should use django reversion to keep track of this one
# even if fixing HEAD may be complicated
class Ruleset(models.Model, Transformable):
    name = models.CharField(max_length=100, unique=True)
    descr = models.CharField(max_length=400, blank=True)
    created_date = models.DateTimeField('date created')
    updated_date = models.DateTimeField('date updated', blank=True)
    need_test = models.BooleanField(default=True)
    validity = models.BooleanField(default=True)
    errors = models.TextField(blank=True)
    rules_count = models.IntegerField(default=0)
    suppressed_sids = models.TextField(verbose_name='Suppress events', default='', blank=True)
    activate_categories = models.BooleanField(default=True)

    editable = True

    # List of Source that can be used in the ruleset
    # It can be a specific version or HEAD if we want to use
    # latest available
    sources = models.ManyToManyField(SourceAtVersion)
    # List of Category selected in the ruleset
    categories = models.ManyToManyField(Category, blank=True)
    rules_transformation = models.ManyToManyField(
        Rule,
        through='RuleTransformation',
        related_name='rules_transformed',
        blank=True
    )
    categories_transformation = models.ManyToManyField(
        Category,
        through='CategoryTransformation',
        related_name='categories_transformed',
        blank=True
    )

    # List or Rules to suppressed from the Ruleset
    # Exported as suppression list in oinkmaster

    # Operations
    # Creation:
    #  - define sources
    #  - define version
    #  - define categories
    #  - define suppressed rules
    # Delete
    # Copy
    #  - Specify new name
    # Refresh:
    #  - trigger update of sources
    #  - build new head
    # Update:
    #  - define version
    #  - update link
    # Generate appliance ruleset to directory:
    #  - get files from correct version exported to directory
    # Apply ruleset:
    #  - Tell Ansible to publish

    def __str__(self):
        return self.name

    def _json_errors(self):
        return json.loads(self.errors)

    json_errors = property(_json_errors)

    def get_processing_filter_thresholds(self):
        for f in self.processing_filters.filter(enabled=True, action='threshold'):
            for item in f.get_threshold_content(self):
                yield item

    def get_user_actions(self, rversion_from, rversion_to, actions_type):
        ua_objects_from = rversion_from.ua_objects.filter(user_action__action_type__in=actions_type)
        ua_objects_to = rversion_to.ua_objects.filter(user_action__action_type__in=actions_type)

        user_action_pk_min = ua_objects_from.filter(
            user_action__action_type__in=actions_type
        ).aggregate(models.Min('user_action__pk')).get('user_action__pk__min')

        user_action_pk_max = ua_objects_to.filter(
            user_action__action_type__in=actions_type
        ).aggregate(models.Max('user_action__pk')).get('user_action__pk__max')

        user_has_all_ua = (ua_objects_from.values('user_action').count() == rversion_from.ua_objects.values('user_action').count()) and \
            (ua_objects_to.values('user_action').count() == rversion_to.ua_objects.values('user_action').count())

        qs = UserAction.objects.none()
        if user_action_pk_min is not None and user_action_pk_max is not None:
            qs = UserAction.objects.filter(
                pk__gte=user_action_pk_min,
                pk__lte=user_action_pk_max,
                action_type__in=actions_type,
                user_action_objects__action_key='ruleset',
                user_action_objects__object_id=self.pk
            ).order_by('-date')
        return qs, user_has_all_ua

    @staticmethod
    def get_transformation_choices(key=Transformation.ACTION):
        # Keys
        ACTION = Transformation.ACTION
        LATERAL = Transformation.LATERAL
        TARGET = Transformation.TARGET

        allowed_choices = []

        if key == ACTION:
            all_choices_set = set(Transformation.ActionTransfoType.get_choices())
            allowed_choices = list(all_choices_set.intersection(set(settings.RULESET_TRANSFORMATIONS)))

            A_BYPASS = Transformation.A_BYPASS
            A_NONE = Transformation.A_NONE

            # TODO: move me in settings.RULESET_TRANSFORMATIONS
            allowed_choices.append((A_BYPASS.value, A_BYPASS.name.title()))
            allowed_choices.append((A_NONE.value, A_NONE.name.title()))

        if key == TARGET:
            CAT_DEFAULT = Transformation.T_CAT_DEFAULT
            RULESET_DEFAULT = Transformation.T_RULESET_DEFAULT

            allowed_choices = list(Transformation.TargetTransfoType.get_choices())
            allowed_choices.remove((CAT_DEFAULT.value, CAT_DEFAULT.name.replace('_', ' ').title()))
            allowed_choices.remove((RULESET_DEFAULT.value, RULESET_DEFAULT.name.replace('_', ' ').title()))

        if key == LATERAL:
            CAT_DEFAULT = Transformation.L_CAT_DEFAULT
            RULESET_DEFAULT = Transformation.L_RULESET_DEFAULT

            allowed_choices = list(Transformation.LateralTransfoType.get_choices())
            allowed_choices.remove((CAT_DEFAULT.value, CAT_DEFAULT.name.replace('_', ' ').title()))
            allowed_choices.remove((RULESET_DEFAULT.value, RULESET_DEFAULT.name.replace('_', ' ').title()))

        return tuple(allowed_choices)

    @staticmethod
    def get_icon():
        return 'fa-th'

    def remove_transformation(self, key):
        RulesetTransformation.objects.filter(
            ruleset_transformation=self,
            key=key.value
        ).delete()

        self.needs_test()
        self.save()

    def set_transformation(self, key=Transformation.ACTION, value=Transformation.A_DROP):
        self.remove_transformation(key)

        r = RulesetTransformation(
            ruleset_transformation=self,
            key=key.value,
            value=value.value
        )
        r.save()

        self.needs_test()
        self.save()

    def get_transformed_categories(self,
                                   key=Transformation.ACTION,
                                   value=Transformation.A_DROP):

        # All transformed categories from this ruleset
        if key is None:
            return Category.objects.filter(categorytransformation__ruleset=self)

        categories = Category.objects.filter(
            categorytransformation__ruleset=self,
            categorytransformation__key=key.value,
            categorytransformation__value=value.value
        )

        return categories

    def get_transformed_rules(self,
                              key=Transformation.ACTION,
                              value=Transformation.A_DROP):

        # All transformed rules from this ruleset
        if key is None:
            return Rule.objects.filter(ruletransformation__ruleset=self)

        rules = Rule.objects.filter(
            ruletransformation__ruleset=self,
            ruletransformation__key=key.value,
            ruletransformation__value=value.value
        )

        return rules

    def get_transformation(self, key=Transformation.ACTION):
        NONE = None
        TYPE = None

        if key == Transformation.ACTION:
            NONE = Transformation.A_NONE
            TYPE = Transformation.ActionTransfoType
        elif key == Transformation.LATERAL:
            NONE = Transformation.L_NO
            TYPE = Transformation.LateralTransfoType
        elif key == Transformation.TARGET:
            NONE = Transformation.T_NONE
            TYPE = Transformation.TargetTransfoType
        else:
            raise Exception("Key '%s' is unknown" % key)

        rt = RulesetTransformation.objects.filter(
            key=key.value,
            ruleset_transformation=self
        ).exclude(value=NONE.value)

        if len(rt) > 0:
            return TYPE(rt[0].value)

        return None

    def is_transformed(self, key=Transformation.ACTION, value=Transformation.A_DROP):
        rulesets_t = Ruleset.objects.filter(
            rulesettransformation__key=key.value,
            rulesettransformation__value=value.value
        )

        return (self.pk in rulesets_t.values_list('pk', flat=True))

    def get_absolute_url(self):
        return reverse('ruleset', args=[str(self.id)])

    def update(self):
        update_errors = []
        is_ti_url = False
        sourcesatversion = self.sources.all()
        for sourcesat in sourcesatversion:
            try:
                sourcesat.source.update()

                if sourcesat.source.method == 'http' and sourcesat.source.is_ti_url() and not is_ti_url:
                    from scirius.utils import get_middleware_module
                    try:
                        get_middleware_module('common').data_export()
                        is_ti_url = True
                    except Exception as exc:
                        request_logger.error('Unable to export data: %s' % exc)
            except IOError as e:
                update_errors.append('Source "%s" update failed:\n\t%s' % (sourcesat.source.name, str(e)))

        # Update timestamp if at least one source update was successful
        if len(sourcesatversion) != 0 and len(sourcesatversion) != len(update_errors):
            self.updated_date = timezone.now()
            self.need_test = True
            self.save()

        if len(update_errors):
            raise IOError(len(update_errors), '\n'.join(update_errors))

    def generate(self):
        sources = self.sources.values_list('source', flat=True)
        rules = Rule.objects.select_related('category').annotate(
            untrusted=models.Case(
                models.When(category__source__untrusted=False, then=False),
                models.When(category__source__untrusted=True, then=True),
                default=True,
                output_field=models.BooleanField()
            ))
        rules = rules.filter(
            category__source__pk__in=sources,
            category__in=self.categories.all(),
            ruleatversion__state=True)

        suppr_rules_pk = SuppressedRuleAtVersion.objects.filter(ruleset=self).values_list('rule_at_version__rule__pk', flat=True).distinct()
        rules = rules.exclude(pk__in=suppr_rules_pk)
        return rules.order_by('sid')

    def generate_threshold(self, directory):
        thresholdfile = os.path.join(directory, 'threshold.config')
        with open(thresholdfile, 'w') as f:
            for threshold in Threshold.objects.filter(ruleset=self):
                f.write("%s\n" % (threshold))

            for threshold in self.get_processing_filter_thresholds():
                f.write(threshold)

            if self.suppressed_sids:
                f.write(self.suppressed_sids)

    def copy(self, name):
        orig_ruleset_pk = self.pk
        orig_sources = self.sources.all()
        orig_categories = self.categories.all()
        self.name = name
        self.pk = None
        self.id = None
        self.created_date = timezone.now()
        self.updated_date = self.created_date
        self.save()
        self.sources.set(orig_sources)
        self.categories.set(orig_categories)
        self.save()
        for truleset in RulesetTransformation.objects.filter(ruleset_transformation_id=orig_ruleset_pk):
            truleset.ruleset_transformation = self
            truleset.pk = None
            truleset.id = None
            truleset.save()
        for threshold in Threshold.objects.filter(ruleset_id=orig_ruleset_pk):
            threshold.ruleset = self
            threshold.pk = None
            threshold.id = None
            threshold.save()
        for tcat in CategoryTransformation.objects.filter(ruleset_id=orig_ruleset_pk):
            tcat.ruleset = self
            tcat.pk = None
            tcat.id = None
            tcat.save()
        for trule in RuleTransformation.objects.filter(ruleset_id=orig_ruleset_pk):
            trule.ruleset = self
            trule.pk = None
            trule.id = None
            trule.save()
        return self

    def export_files(self, directory):
        cats_content = ''
        iprep_content = ''
        for src in self.sources.all():
            cats, iprep = src.export_files(directory)
            if cats_content and cats:
                cats_content += '\n'
            cats_content += cats

            if iprep_content and iprep:
                iprep_content += '\n'
            iprep_content += iprep

        # generate threshold.config
        self.generate_threshold(directory)
        return cats_content, iprep_content

    def diff(self, mode='long'):
        sourcesatversion = self.sources.all()
        sdiff = {}
        for sourceat in sourcesatversion:
            supdate = SourceUpdate.objects.filter(source=sourceat.source).order_by('-created_date')
            if len(supdate) > 0:
                srcdiff = supdate[0].diff()
                if mode == 'short':
                    num = 0
                    for key in srcdiff['stats']:
                        num = num + srcdiff['stats'][key]
                    if num > 0:
                        sdiff[sourceat.name] = srcdiff
                else:
                    sdiff[sourceat.name] = srcdiff
        return sdiff

    def to_buffer(self):
        from scirius.utils import get_middleware_module

        rules = self.generate()
        self.number_of_rules(rules)

        # test is not done on stamus source
        sources = get_middleware_module('common').custom_source_datatype()
        rules = rules.exclude(category__source__datatype__in=sources)
        file_content = "# Rules file for %s generated by Scirius at %s\n" % (self.name, str(timezone.now()))

        if len(rules) > 0:
            try:
                Rule.enable_cache()

                rules_content = []
                for rule in rules:
                    # All rules are at version = 0 while test
                    # is not done on stamus source
                    c = rule.generate_content(self, version=0)
                    if c:
                        rules_content.append(c)
                file_content += "\n".join(rules_content)
            finally:
                Rule.disable_cache()

        return file_content

    def number_of_rules(self, rules=None):
        if rules is None:
            rules = self.generate()

        self.rules_count = len(rules)
        self.save()
        result = {'rules_count': self.rules_count}
        return result

    def test_rule_buffer(self, rule_buffer, single=False):
        testor = TestRules()
        tmpdir = tempfile.mkdtemp()
        cats_content, iprep_content = self.export_files(tmpdir)
        related_files = {}
        for root, _, files in os.walk(tmpdir):
            for f in files:
                fullpath = os.path.join(root, f)
                with open(fullpath, 'r') as cf:
                    related_files[f] = cf.read(50 * 1024)
        shutil.rmtree(tmpdir)

        return testor.check_rule_buffer(
            rule_buffer,
            related_files=related_files,
            single=single,
            cats_content=cats_content,
            iprep_content=iprep_content
        )

    def test(self):
        self.need_test = False
        rule_buffer = self.to_buffer()
        result = self.test_rule_buffer(rule_buffer)
        result['rules_count'] = self.rules_count
        self.validity = result['status']
        if 'errors' in result:
            self.errors = json.dumps(result['errors'])
        else:
            self.errors = json.dumps([])
        self.save()
        return result

    def disable_rules_at_version(self, ravs):
        suppr_ravs = []
        for rav in ravs:
            if SuppressedRuleAtVersion.objects.filter(ruleset=self, rule_at_version=rav).count() == 0:
                suppr_ravs.append(SuppressedRuleAtVersion(ruleset=self, rule_at_version=rav))

        if len(suppr_ravs):
            SuppressedRuleAtVersion.objects.bulk_create(suppr_ravs)
            self.needs_test()

    def enable_rules_at_version(self, ravs):
        restore_ravs = []
        for rav in ravs:
            if SuppressedRuleAtVersion.objects.filter(ruleset=self, rule_at_version=rav).count() > 0:
                restore_ravs.append(rav)

        if len(restore_ravs):
            SuppressedRuleAtVersion.objects.filter(rule_at_version__in=restore_ravs, ruleset=self).delete()
            self.needs_test()

    def needs_test(self):
        self.need_test = True
        self.save()

    @classmethod
    def create_ruleset(cls, name, sources=[], activate_categories=False):
        ruleset = cls.objects.create(
            name=name,
            created_date=timezone.now(),
            updated_date=timezone.now(),
            activate_categories=activate_categories
        )

        for src in sources:
            src_at_version = SourceAtVersion.objects.get(pk=src)
            ruleset.sources.add(src_at_version)
            if activate_categories:
                for cat in Category.objects.filter(source=src_at_version.source):
                    ruleset.categories.add(cat)

        return ruleset


class RuleTransformation(Transformation):
    ruleset = models.ForeignKey(Ruleset, on_delete=models.CASCADE)
    rule_transformation = models.ForeignKey(Rule, on_delete=models.CASCADE)

    class Meta:
        unique_together = ('ruleset', 'rule_transformation', 'key')


class SuppressedRuleAtVersion(models.Model):
    ruleset = models.ForeignKey(Ruleset, on_delete=models.CASCADE)
    rule_at_version = models.ForeignKey(RuleAtVersion, on_delete=models.CASCADE)

    class Meta:
        unique_together = ('ruleset', 'rule_at_version')


class CategoryTransformation(Transformation):
    ruleset = models.ForeignKey(Ruleset, on_delete=models.CASCADE)
    category_transformation = models.ForeignKey(Category, on_delete=models.CASCADE)

    class Meta:
        unique_together = ('ruleset', 'category_transformation', 'key')


class RulesetTransformation(Transformation):
    ruleset_transformation = models.ForeignKey(Ruleset, on_delete=models.CASCADE)

    class Meta:
        unique_together = ('ruleset_transformation', 'key')


class Threshold(models.Model):
    THRESHOLD_TYPES = (('threshold', 'threshold'), ('suppress', 'suppress'))
    THRESHOLD_TYPE_TYPES = (('limit', 'limit'), ('threshold', 'threshold'), ('both', 'both'))
    TRACK_BY_CHOICES = (('by_src', 'by_src'), ('by_dst', 'by_dst'))
    descr = models.CharField(max_length=400, blank=True)
    threshold_type = models.CharField(max_length=20, choices=THRESHOLD_TYPES, default='suppress')
    type = models.CharField(max_length=20, choices=THRESHOLD_TYPE_TYPES, default='limit')
    gid = models.IntegerField(default=1)
    rule = models.ForeignKey(Rule, default=None, on_delete=models.CASCADE)
    ruleset = models.ForeignKey(Ruleset, default=None, on_delete=models.CASCADE)
    track_by = models.CharField(max_length=10, choices=TRACK_BY_CHOICES, default='by_src')
    net = models.CharField(max_length=100, blank=True, validators=[validate_addresses_or_networks])
    count = models.IntegerField(default=1)
    seconds = models.IntegerField(default=60)

    def __str__(self):
        rep = ""
        if self.threshold_type == "suppress":
            net = self.net
            if ',' in self.net:
                net = '[%s]' % self.net

            rep = "suppress gen_id %d, sig_id %d" % (self.gid, self.rule.sid)
            rep += ", track %s, ip %s" % (self.track_by, net)
        else:
            rep = "%s gen_id %d, sig_id %d, type %s, track %s, count %d, seconds %d" % (self.threshold_type, self.gid, self.rule.sid, self.type, self.track_by, self.count, self.seconds)
        return rep

    def get_absolute_url(self):
        return reverse('threshold', args=[str(self.id)])

    def contain(self, elt):
        if elt.threshold_type != self.threshold_type:
            return False

        if elt.track_by != self.track_by:
            return False

        if elt.threshold_type == 'suppress':
            if not IPy.IP(self.net).overlaps(IPy.IP(elt.net)):
                return False

        return True


class RuleProcessingFilter(models.Model):
    action = models.CharField(max_length=10)
    options = models.CharField(max_length=512, null=True, blank=True)
    index = models.PositiveIntegerField()
    description = models.TextField(default='')
    enabled = models.BooleanField(default=True)
    rulesets = models.ManyToManyField(Ruleset, related_name='processing_filters')
    imported = models.BooleanField(default=False)
    event_type = models.CharField(max_length=32, default='alert', null=False, blank=False)

    class Meta:
        ordering = ['index']

    def get_options(self):
        if not self.options:
            return {}
        return json.loads(self.options)

    def get_threshold_content(self, ruleset=None):
        sid_track_ip = {}
        sids = []
        try:
            sid = self.filter_defs.get(key='alert.signature_id').value
            sid_track_ip = {str(sid): []}
            sids.append(sid)
        except models.ObjectDoesNotExist:
            pass

        try:
            msg = self.filter_defs.get(key='msg').value
            sids = list(Rule.objects.filter(msg__icontains=msg).order_by('sid').values_list('sid', flat=True))
            sid_track_ip = dict([(str(sid_), []) for sid_ in sids]) if msg else None
        except models.ObjectDoesNotExist:
            pass

        try:
            content = self.filter_defs.get(key='content').value
            sids = list(Rule.objects.filter(content__icontains=content).order_by('sid').values_list('sid', flat=True))
            sid_track_ip = dict([(str(sid_), []) for sid_ in sids]) if content else None
        except models.ObjectDoesNotExist:
            pass

        try:
            msg = self.filter_defs.get(key='alert.signature').value
            sids = list(Rule.objects.filter(msg=msg).order_by('sid').values_list('sid', flat=True))
            sid_track_ip = dict([(str(sid), []) for sid in sids]) if msg else None
        except models.ObjectDoesNotExist:
            pass

        if self.action == 'suppress':
            try:
                src_ip = self.filter_defs.get(key='src_ip')
            except models.ObjectDoesNotExist:
                src_ip = None

            try:
                dest_ip = self.filter_defs.get(key='dest_ip')
            except models.ObjectDoesNotExist:
                dest_ip = None

            try:
                alert_target_ip = self.filter_defs.get(key='alert.target.ip')
            except models.ObjectDoesNotExist:
                alert_target_ip = None

            try:
                alert_source_ip = self.filter_defs.get(key='alert.source.ip')
            except models.ObjectDoesNotExist:
                alert_source_ip = None

            if alert_source_ip or alert_target_ip:
                rules = Rule.objects.filter(sid__in=sids).annotate(
                    untrusted=models.Case(
                        models.When(category__source__untrusted=False, then=False),
                        models.When(category__source__untrusted=True, then=True),
                        default=True,
                        output_field=models.BooleanField()
                    ))

                alert_ip = alert_source_ip if alert_source_ip is not None else alert_target_ip

                for rule in rules:
                    content = rule.generate_content(ruleset)

                    if 'target:src_ip;' in content:
                        if alert_target_ip:
                            sid_track_ip[str(rule.sid)] = ('by_src', alert_ip.value,)
                        elif alert_source_ip:
                            sid_track_ip[str(rule.sid)] = ('by_dst', alert_ip.value,)
                    elif 'target:dest_ip;' in content:
                        if alert_target_ip:
                            sid_track_ip[str(rule.sid)] = ('by_dst', alert_ip.value,)
                        elif alert_source_ip:
                            sid_track_ip[str(rule.sid)] = ('by_src', alert_ip.value,)
                    else:
                        sid_track_ip.pop(str(rule.sid), None)

            elif src_ip:
                for sid in sids:
                    sid_track_ip[str(sid)] = ('by_src', src_ip.value)
            else:
                for sid in sids:
                    sid_track_ip[str(sid)] = ('by_dst', dest_ip.value)

            res = []
            for sid, val in sorted(sid_track_ip.items()):
                if len(val):
                    res.append('suppress gen_id 1, sid_id %s, track %s, ip %s\n' % (sid, val[0], val[1]))
            return res

        elif self.action == 'threshold':
            options = self.get_options()

            res = []
            for sid in sid_track_ip.keys():
                res.append('threshold gen_id 1, sig_id %s, type %s, track %s, count %s, seconds %s\n' % (sid, options['type'], options['track'], options['count'], options['seconds']))
            return res

        raise Exception('Invalid processing filter action %s' % self.action)

    @staticmethod
    def get_icon():
        return 'pficon-filter'

    def __str__(self):
        filters = []
        for f in self.filter_defs.order_by('key'):
            filters.append(str(f))
        return '%s (%s)' % (self.action, ', '.join(filters))


class RuleProcessingFilterDef(models.Model):
    OPERATOR = (('equal', 'Equal'), ('different', 'Different'), ('contains', 'Contains'))
    OPERATOR_DISPLAY = {
        'equal': '=',
        'different': '!='
    }

    key = models.CharField(max_length=512)
    value = models.CharField(max_length=512)
    operator = models.CharField(max_length=10, choices=OPERATOR)
    proc_filter = models.ForeignKey(RuleProcessingFilter, on_delete=models.CASCADE, related_name='filter_defs')
    full_string = models.BooleanField(default=True)

    class Meta:
        ordering = ('key', 'value')

    def __str__(self):
        op = self.OPERATOR_DISPLAY.get(self.operator, self.operator)
        return '%s %s %s' % (self.key, op, self.value)


def dependencies_check(obj):
    if obj == Source:
        return

    if obj == Ruleset:
        if len(Source.objects.all()) == 0:
            return "You need first to create and update a source."
        if len(SourceAtVersion.objects.all()) == 0:
            return "You need first to update existing source."
        return

    if len(Source.objects.all()) == 0:
        return "You need first to create a source and a ruleset."

    if len(Ruleset.objects.all()) == 0:
        return "You need first to create a ruleset."


def export_iprep_files(target_dir, cats_content, iprep_content):
    group_rules = Rule.objects.filter(group=True)
    cat_map = {}

    with open(target_dir + "/" + "scirius-categories.txt", 'w') as rfile:
        index = 1
        for rule in group_rules:
            rfile.write('%s,%d,%s\n' % (index, rule.sid, rule.msg))
            cat_map[index] = rule
            index = index + 1
        if cats_content:
            rfile.write(cats_content)

    with open(target_dir + "/" + "scirius-iprep.list", 'w') as rfile:
        for cate in cat_map:
            for IP in cat_map[cate].group_ips_list.split(','):
                rfile.write('%s,%d,100\n' % (IP, cate))
        if iprep_content:
            rfile.write(iprep_content)
