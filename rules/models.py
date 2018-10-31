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
from __future__ import unicode_literals
from django.db import models
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey, GenericRelation
from django.conf import settings
from django.core.exceptions import FieldError, SuspiciousOperation, ValidationError
from django.core.validators import validate_ipv4_address
from django.db import transaction
from django.utils import timezone
from django.utils.html import mark_safe, format_html, format_html_join
from django.db.models import Q
from idstools import rule as rule_idstools
from enum import Enum, unique
from copy import deepcopy
from collections import OrderedDict
import requests
import tempfile
import tarfile
import re
import sys
import os
import git
import shutil
import json
import IPy
from datetime import date as datetime_date

from rules.tests_rules import TestRules

from django.contrib.auth.models import User


_HUNT_FILTERS = [
                    {
                      'id': 'hits_min',
                      'title': 'Hits min',
                      'placeholder': 'Minimum Hits Count',
                      'filterType': 'number',
                      'valueType': 'positiveint',
                      'queryType': 'rest'
                    },
                    {
                      'id': 'hits_max',
                      'title': 'Hits max',
                      'placeholder': 'Maximum Hits Count',
                      'filterType': 'number',
                      'valueType': 'positiveint',
                      'queryType': 'rest'
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
                      'id': 'search',
                      'title': 'Content',
                      'placeholder': 'Filter by Content',
                      'filterType': 'text',
                      'valueType': 'text',
                      'queryType': 'rest'
                    }, {
                      'id': 'alert.signature_id',
                      'title': 'Signature ID',
                      'placeholder': 'Filter by Signature ID',
                      'filterType': 'number',
                      'valueType': 'positiveint',
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
                                  {'id': 'http_length', 'title': 'Length', 'placeholder': 'Filter by Content Length'},
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
                                  {'id': 'subject', 'title': 'Subject', 'placeholder': 'Filter by Subject'},
                                  {'id': 'issuerdn', 'title': 'Issuer', 'placeholder': 'Filter by Issuer'},
                                  {'id': 'sni', 'title': 'Server Name Indication', 'placeholder': 'Filter by Server Name Indication'},
                                  {'id': 'version', 'title': 'Version', 'placeholder': 'Filter by Version'},
                                  {'id': 'fingerprint', 'title': 'Fingerprint', 'placeholder': 'Filter by Fingerprint'},
                                  {'id': 'serial', 'title': 'Serial', 'placeholder': 'Filter by Serial'},
                                  {'id': 'ja3.hash', 'title': 'JA3 Hash', 'placeholder': 'Filter by JA3 Hash'},
                               ]
                          },
                       ]
                    }
                ]


def get_hunt_filters():
    return deepcopy(_HUNT_FILTERS)


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

    if ':' in netloc:
        netloc, port = netloc.split(':', 1)
        validate_port(port)

    validate_hostname(netloc)


class UserAction(models.Model):
    ACTIONS = OrderedDict([
               # Login/Logout
               ('login', {
                    'description': 'Logged in as {user}',
                    'title': 'Login'
                }),
               ('logout', {
                    'description': '{user} has logged out',
                    'title': 'Logout'
                }),

               # Sources:
               ('create_source', {
                    'description': '{user} has created source {source}',
                    'title': 'Create Source'
                }),
               ('update_source', {
                    'description': '{user} has updated source {source}',
                    'title': 'Update Source'
                }),
               ('edit_source', {
                    'description': '{user} has edited source {source}',
                    'title': 'Edit Source'
                }),
               ('upload_source', {
                    'description': '{user} has uploaded source {source}',
                    'title': 'Upload Source'
                }),
               ('enable_source', {
                    'description': '{user} has enabled source {source} in ruleset {ruleset}',
                    'title': 'Enable Source'
                }),
               ('disable_source', {
                    'description': '{user} has disabled source {source} in ruleset {ruleset}',
                    'title': 'Disable Source'
                }),
               ('delete_source', {
                    'description': '{user} has deleted source {source}',
                    'title': 'Delete Source'
                }),

               # Rulesets:
               ('create_ruleset', {
                    'description': '{user} has created ruleset {ruleset}',
                    'title': 'Create Ruleset'
                }),
               ('transform_ruleset', {
                    'description': '{user} has transformed ruleset {ruleset} to {transformation}',
                    'title': 'Transform Ruleset'
                }),
               ('edit_ruleset', {
                   'description': '{user} has edited ruleset {ruleset}',
                   'title': 'Edit Ruleset'
                }),
               ('copy_ruleset', {
                   'description': '{user} has copied ruleset {ruleset}',
                   'title': 'Copy Ruleset'
                }),
               ('delete_ruleset', {
                    'description': '{user} has deleted ruleset {ruleset}',
                    'title': 'Delete Ruleset'
                }),

               # Categories:
               ('enable_category', {
                    'description': '{user} has enabled category {category} in ruleset {ruleset}',
                    'title': 'Enable Category'
                }),
               ('transform_category', {
                    'description': '{user} has transformed category {category} to {transformation} in ruleset {ruleset}',
                    'title': 'Transform Category'
                }),
               ('disable_category', {
                    'description': '{user} has disabled category {category} in ruleset {ruleset}',
                    'title': 'Disable Category'
                }),

               # Rules:
               ('enable_rule', {
                    'description': '{user} has enabled rule {rule} in ruleset {ruleset}',
                    'title': 'Enable Rule'
                }),
               ('comment_rule', {
                    'description': '{user} has commented rule {rule}',
                    'title': 'Comment Rule'
                }),
               ('transform_rule', {
                    'description': '{user} has transformed rule {rule} to {transformation} in ruleset {ruleset}',
                    'title': 'Transform Rule'
                }),
               ('suppress_rule', {
                    'description': '{user} has suppressed rule {rule} in ruleset {ruleset}',
                    'title': 'Suppress Rule'
                }),
               ('disable_rule', {
                    'description': '{user} has disabled rule {rule} in ruleset {ruleset}',
                    'title': 'Disable Rule'
                }),
               ('delete_suppress_rule', {
                    'description': '{user} has deleted suppressed rule {rule} in ruleset {ruleset}',
                    'title': 'Delete Suppress Rule'
                }),

               # Toggle availability
               ('toggle_availability', {
                    'description': '{user} has modified rule availability {rule}',
                    'title': 'Toggle Availability'
                }),

               # Thresholds:
               ('create_threshold', {
                    'description': '{user} has created threshold on rule {rule} in ruleset {ruleset}',
                    'title': 'Create Threshold'
                }),
               ('edit_threshold', {
                    'description': '{user} has edited threshold {threshold} on rule {rule} in ruleset {ruleset}',
                    'title': 'Edit Threshold'
                }),
               ('delete_threshold', {
                    'description': '{user} has deleted threshold {threshold} on rule {rule} in ruleset {ruleset}',
                    'title': 'Delete Threshold'
                }),

                # Used only in REST API
               ('delete_transform_ruleset', {
                    'description': '{user} has deleted transformation {transformation} on ruleset {ruleset}',
                    'title': 'Deleted Ruleset Transformation'
                }),
               ('delete_transform_rule', {
                    'description': '{user} has deleted transformation {transformation} on rule {rule} in ruleset {ruleset}',
                    'title': 'Delete Rule Transformation'
                }),
               ('delete_transform_category', {
                    'description': '{user} has deleted transformation {transformation} on category {category} in ruleset {ruleset}',
                    'title': 'Delete Category Transformation'
                }),
               # End REST API

               # Suricata
               ('edit_suricata', {
                    'description': '{user} has edited suricata',
                    'title': 'Edit Suricata'
                }),
               ('create_suricata', {
                    'description': '{user} has created suricata',
                    'title': 'Create Suricata'
                }),
               ('update_push_all', {
                    'description': '{user} has pushed ruleset {ruleset}',
                    'title': 'Update/Push ruleset'
                }),

               # Settings
               ('system_settings', {
                    'description': '{user} has edited system settings',
                    'title': 'Edit System Settings'
                }),
               ('delete_alerts', {
                    'description': '{user} has deleted alerts from rule {rule}',
                    'title': 'Delete Alerts'
                }),

               # Rule processing filter
               ('create_rule_filter', {
                    'description': '{user} has created rule filter {rule_filter}',
                    'title': 'Create rule filter'
                }),
               ('edit_rule_filter', {
                    'description': '{user} has edited rule filter {rule_filter}',
                    'title': 'Edit rule filter'
                }),
               ('delete_rule_filter', {
                    'description': '{user} has deleted rule filter {rule_filter}',
                    'title': 'Delete rule filter'
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

    def __init__(self, *args, **kwargs):
        super(UserAction, self).__init__(*args, **kwargs)
        if not self.username and self.user:
            self.username = self.user.username

    def __unicode__(self):
        return self.generate_description()

    @classmethod
    def create(cls, **kwargs):
        if 'action_type' not in kwargs:
            raise Exception('Cannot create UserAction without "action_type"')

        force_insert = True if 'force_insert' in kwargs and kwargs.pop('force_insert') else False

        # UserAction
        ua_params = {}
        for param in ('action_type', 'comment', 'user'):
            if param in kwargs:
                ua_params[param] = kwargs.pop(param)

        ua = cls(**ua_params)
        ua.save(force_insert)

        # UserActionObject
        for action_key, action_value in kwargs.iteritems():

            ua_obj_params = {
                'action_key': action_key,
                'action_value': unicode(action_value)[:100],
                'user_action': ua,
            }

            if not isinstance(action_value, (str, unicode,)):
                ua_obj_params['content'] = action_value

            ua_obj = UserActionObject(**ua_obj_params)
            ua_obj.save()

        # Used as test
        ua.generate_description()

        # Warning; do not remove.
        # hack callback is called after UserAction.save is called. So the
        # 2nd save will trigger the callback, once UserActionObject
        # have been created
        ua.save()

    def generate_description(self):
        if self.description:
            return self.description

        from scirius.utils import get_middleware_module
        actions_dict = get_middleware_module('common').get_user_actions_dict()
        if self.action_type not in actions_dict.keys():
            raise Exception('Unknown action type "%s"' % self.action_type)

        format_ = {'user': format_html('<strong>{}</strong>', self.username), 'datetime': self.date}
        actions = UserActionObject.objects.filter(user_action=self).all()

        for action in actions:
            if action.content and hasattr(action.content, 'get_absolute_url'):
                format_[action.action_key] = format_html('<a href="{}"><strong>{}</strong></a>',
                                                         action.content.get_absolute_url(),
                                                         action.action_value)
            else:
                format_[action.action_key] = format_html('<strong>{}</strong>', action.action_value)

        try:
            html = format_html(actions_dict[self.action_type]['description'], **format_)
        except KeyError as e:
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
        if self.action_type not in actions_dict.keys():
            raise Exception('Unknown action type "%s"' % self.action_type)

        return actions_dict[self.action_type]['title']

    @staticmethod
    def get_icon():
        return 'pficon-user'

    def get_icons(self):
        from scirius.utils import get_middleware_module
        actions_dict = get_middleware_module('common').get_user_actions_dict()
        actions = UserActionObject.objects.filter(user_action=self).all()

        icons = [(self.get_icon(), self.username)]
        for action in actions:

            # ==== Coner cases
            # transformation is str type
            # or workaround for UserAction which can contains no instance but str (ex: create a source without a ruleset)
            if action.action_key == 'transformation' or (action.action_key == 'ruleset' and action.action_value == 'No Ruleset'):
                continue

            ct = action.content_type
            klass = ct.model_class()

            if hasattr(klass, 'get_icon'):
                lb = action.action_value

                icon = klass.get_icon()
                instances = klass.objects.filter(pk=action.object_id).all()

                if len(instances):
                    if isinstance(instances[0], Source):
                        icon = Source.get_icon(instances[0])

                    if isinstance(instances[0], Rule):
                        lb = instances[0].pk

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
    http_proxy = models.CharField(max_length=200, validators=[validate_proxy], default="", blank=True,
                                    help_text='Proxy address of the form "host:port".')
    https_proxy = models.CharField(max_length=200, validators=[validate_proxy], default="", blank=True)
    use_elasticsearch = models.BooleanField(default=True)
    custom_elasticsearch = models.BooleanField(default=False)
    elasticsearch_url = models.CharField(max_length=200, validators=[validate_url], blank=True,
                                    default='http://elasticsearch:9200/')

    def get_proxy_params(self):
        if self.use_http_proxy:
            return { 'http': self.http_proxy, 'https': self.https_proxy }
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
    gsettings = get_system_settings()
    if gsettings.custom_elasticsearch:
        addr = gsettings.elasticsearch_url
        if not addr.endswith('/'):
            addr += '/'
        return addr
    return 'http://%s/' % settings.ELASTICSEARCH_ADDRESS

def get_es_path(path):
    return get_es_address() + path.lstrip('/')

class Source(models.Model):
    FETCH_METHOD = (
        ('http', 'HTTP URL'),
#        ('https', 'HTTPS URL'),
        ('local', 'Upload'),
    )
    CONTENT_TYPE = (
        ('sigs', 'Signatures files in tar archive'),
        ('sig', 'Individual Signatures file'),
#        ('iprep', 'IP reputation files'),
        ('other', 'Other content'),
    )
    TMP_DIR = "/tmp/"

    name = models.CharField(max_length=100, unique = True)
    created_date = models.DateTimeField('date created')
    updated_date = models.DateTimeField('date updated', blank = True, null = True)
    method = models.CharField(max_length=10, choices=FETCH_METHOD)
    datatype = models.CharField(max_length=10, choices=CONTENT_TYPE)
    uri = models.CharField(max_length=400, blank = True, null = True)
    cert_verif = models.BooleanField('Check certificates', default=True)
    authkey = models.CharField(max_length=400, blank = True, null = True)
    cats_count = models.IntegerField(default = 0)
    rules_count = models.IntegerField(default = 0)
    public_source = models.CharField(max_length=100, blank = True, null = True)
    use_iprep = models.BooleanField('Use IP reputation for group signatures', default=True)

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

    def __init__(self, *args, **kwargs):
        models.Model.__init__(self, *args, **kwargs)
        if (self.method == 'http'):
            self.update_ruleset = self.update_ruleset_http
        else:
            self.update_ruleset = None
        self.first_run = False
        self.updated_rules = {"added": [], "deleted": [], "updated": []}
        if len(Flowbit.objects.filter(source = self)) == 0:
            self.init_flowbits = True
        else:
            self.init_flowbits = False

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

    def __unicode__(self):
        return self.name

    def aggregate_update(self, update):
        self.updated_rules["added"] = list(set(self.updated_rules["added"]).union(set(update["added"])))
        self.updated_rules["deleted"] = list(set(self.updated_rules["deleted"]).union(set(update["deleted"])))
        self.updated_rules["updated"] = list(set(self.updated_rules["updated"]).union(set(update["updated"])))

    def get_categories(self):
        source_git_dir = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.pk))
        catname = re.compile("(.+)\.rules$")
        existing_rules_hash = {}
        for rule in Rule.objects.all().prefetch_related('category'):
            existing_rules_hash[rule.sid] = rule
        for f in os.listdir(os.path.join(source_git_dir, 'rules')):
            if f.endswith('.rules'):
                match = catname.search(f)
                name = match.groups()[0]
                category = Category.objects.filter(source = self, name = name)
                if not category:
                    category = Category.objects.create(source = self,
                                            name = name, created_date = timezone.now(),
                                            filename = os.path.join('rules', f))
                else:
                    category = category[0]
                category.get_rules(self, existing_rules_hash = existing_rules_hash)
                # get rules in this category
        for category in Category.objects.filter(source = self):
            if not os.path.isfile(os.path.join(source_git_dir, category.filename)):
                category.delete()

    def get_git_repo(self, delete = False):
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
            del(config)
            del(repo)
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
        sversions  = SourceAtVersion.objects.filter(source = self, version = version)
        if sversions:
            sversions[0].updated_date = self.updated_date
            sversions[0].save()
        else:
            sversion = SourceAtVersion.objects.create(source = self, version = version,
                                                    updated_date = self.updated_date, git_version = version)

    def handle_rules_in_tar(self, f):
        f.seek(0)
        if (not tarfile.is_tarfile(f.name)):
            raise OSError("Invalid tar file")

        self.updated_date = timezone.now()
        self.first_run = False

        repo = self.get_git_repo(delete = True)

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
            # don't allow tar file with file in root dir
            if member.isfile() and not '/' in member.name:
                raise SuspiciousOperation("Suspect tar file contains file in root directory '%s' instead of under 'rules' directory" % (member.name))
            if member.isdir() and ('/' + member.name).endswith('/rules'):
                if rules_dir:
                    raise SuspiciousOperation("Tar file contains two 'rules' directory instead of one")
                dir_list.append(member)
                rules_dir = member.name
            if member.isfile() and member.name.split('/')[-2] == 'rules':
                dir_list.append(member)
        if rules_dir == None:
            raise SuspiciousOperation("Tar file does not contain a 'rules' directory")

        source_git_dir = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.pk))
        tfile.extractall(path=source_git_dir, members = dir_list)
        if "/" in rules_dir:
            shutil.move(os.path.join(source_git_dir, rules_dir), os.path.join(source_git_dir, 'rules'))
            shutil.rmtree(os.path.join(source_git_dir, rules_dir.split('/')[0]))

        index = repo.index
        if len(index.diff(None)) or self.first_run:
            os.environ['USERNAME'] = 'scirius'
            index.add(['rules'])
            message =  'source version at %s' % (self.updated_date)
            index.commit(message)

        self.save()
        # Now we must update SourceAtVersion for this source
        # or create it if needed
        self.create_sourceatversion()
        # Get categories
        self.get_categories()

    def handle_other_file(self, f):
        self.updated_date = timezone.now()
        self.first_run = False

        repo = self.get_git_repo(delete = True)

        rules_dir = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.pk), 'rules')
        # create rules dir if needed
        if not os.path.isdir(rules_dir):
            os.makedirs(rules_dir)
        # copy file content to target
        f.seek(0)
        os.fsync(f)
        shutil.copy(f.name, os.path.join(rules_dir, self.name))

        index = repo.index
        if len(index.diff(None)) or self.first_run:
            os.environ['USERNAME'] = 'scirius'
            index.add(['rules'])
            message =  'source version at %s' % (self.updated_date)
            index.commit(message)

        self.save()
        # Now we must update SourceAtVersion for this source
        # or create it if needed
        self.create_sourceatversion()

    def handle_rules_file(self, f):

        f.seek(0)
        if (tarfile.is_tarfile(f.name)):
            raise OSError("This is a tar file and not a individual signature file, please select another category")
        f.seek(0)

        self.updated_date = timezone.now()
        self.first_run = False

        repo = self.get_git_repo(delete = True)

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
            message =  'source version at %s' % (self.updated_date)
            index.commit(message)

        self.save()
        # Now we must update SourceAtVersion for this source
        # or create it if needed
        self.create_sourceatversion()
        # category based on filename
        category = Category.objects.filter(source = self, name = '%s Sigs' % (self.name))
        if not category:
            category = Category.objects.create(source = self,
                                    name = '%s Sigs' % (self.name), created_date = timezone.now(),
                                    filename = os.path.join('rules', 'sigs.rules'))
            category.get_rules(self)
        else:
            category[0].get_rules(self)

    def json_rules_list(self, rlist):
        rules = []
        for rule in rlist:
            rules.append({"sid":rule.sid, "msg": rule.msg,
                "category": rule.category.name,
                "pk": rule.pk })
        # for each rule we create a json object sid + msg + content
        return rules

    def create_update(self):
        # for each set
        update = {}
        update["deleted"] = self.json_rules_list(self.updated_rules["deleted"])
        update["added"] = self.json_rules_list(self.updated_rules["added"])
        update["updated"] = self.json_rules_list(self.updated_rules["updated"])
        repo = self.get_git_repo(delete = False)
        sha = repo.heads.master.log()[-1].newhexsha
        SourceUpdate.objects.create(
            source = self,
            created_date = timezone.now(),
            data = json.dumps(update),
            version = sha,
            changed = len(update["deleted"]) + len(update["added"]) + len(update["updated"]),
        )


    def build_counters(self):
        cats = Category.objects.filter(source = self)
        self.cats_count = len(cats)
        self.rules_count = len(Rule.objects.filter(category__in = cats))
        self.save()

    # This method cannot be called twice consecutively
    @transaction.atomic
    def update(self):
        # look for categories list: if none, first import
        categories = Category.objects.filter(source = self)
        firstimport = False
        if not categories:
            firstimport = True
        if not self.method in ['http', 'local']:
            raise FieldError("Currently unsupported method")
        if self.update_ruleset:
            f = tempfile.NamedTemporaryFile(dir=self.TMP_DIR)
            self.update_ruleset(f)
            if self.datatype == 'sigs':
                self.handle_rules_in_tar(f)
            elif self.datatype == 'sig':
                self.handle_rules_file(f)
            elif self.datatype == 'other':
                self.handle_other_file(f)
        if not self.datatype == 'other' and not firstimport:
            self.create_update()
        for rule in self.updated_rules["deleted"]:
            rule.delete()
        self.needs_test()

    def diff(self):
        source_git_dir = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.pk))
        if not os.path.isdir(source_git_dir):
            raise IOError("You have to update source first")
        repo = git.Repo(source_git_dir)
        hcommit = repo.head.commit
        return hcommit.diff('HEAD~1', create_patch = True)

    def export_files(self, directory, version):
        source_git_dir = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.pk))
        repo = git.Repo(source_git_dir)
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
                if member.name.endswith('.rules') and not self.datatype == 'other':
                    continue
                if member.isfile():
                    member.name = os.path.join(*member.name.split("/", 2)[1:])
                    mfile = tfile.extract(member, path=directory)

    def get_absolute_url(self):
        from django.core.urlresolvers import reverse
        return reverse('source', args=[str(self.id)])

    def update_ruleset_http(self, f):
        proxy_params = get_system_settings().get_proxy_params()
        hdrs = { 'User-Agent': 'scirius' }
        if self.authkey:
            hdrs['Authorization'] = self.authkey
        try:
            if proxy_params:
                resp = requests.get(self.uri, proxies = proxy_params, headers = hdrs, verify = self.cert_verif)
            else:
                resp = requests.get(self.uri, headers = hdrs, verify = self.cert_verif)
            resp.raise_for_status()
        except requests.exceptions.ConnectionError, e:
            if "Name or service not known" in str(e):
                raise IOError("Connection error 'Name or service not known'")
            elif "Connection timed out" in str(e):
                raise IOError("Connection error 'Connection timed out'")
            else:
                raise IOError("Connection error '%s'" % (e))
        except requests.exceptions.HTTPError:
            if resp.status_code == 404:
                raise IOError("URL not found on server (error 404), please check URL")
            raise IOError("HTTP error %d sent by server, please check URL or server" % (resp.status_code))
        except requests.exceptions.Timeout:
            raise IOError("Request timeout, server may be down")
        except requests.exceptions.TooManyRedirects:
            raise IOError("Too many redirects, server may be broken")
        f.write(resp.content)

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

    def new_uploaded_file(self, f, firstimport):
        self.handle_uploaded_file(f)
        if not self.datatype == 'other' and not firstimport:
            self.create_update()
        for rule in self.updated_rules["deleted"]:
            rule.delete()
        self.needs_test()

    def needs_test(self):
        try:
            sourceatversion = SourceAtVersion.objects.get(source = self, version = 'HEAD')
        except:
            return
        rulesets = Ruleset.objects.all()
        for ruleset in rulesets:
            if sourceatversion in ruleset.sources.all():
                ruleset.needs_test()


class UserActionObject(models.Model):
    action_key = models.CharField(max_length=20)
    action_value = models.CharField(max_length=100)

    user_action = models.ForeignKey(UserAction, related_name='user_action_objects')
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, null=True)
    object_id = models.PositiveIntegerField(null=True)
    content = GenericForeignKey('content_type', 'object_id')


class SourceAtVersion(models.Model):
    source = models.ForeignKey(Source)
    # Sha1 or HEAD or tag
    version = models.CharField(max_length=42)
    git_version = models.CharField(max_length=42, default = 'HEAD')
    updated_date = models.DateTimeField('date updated', blank = True, default = timezone.now)

    def __unicode__(self):
        return unicode(self.source) + "@" + self.version

    def _get_name(self):
        return unicode(self)

    name = property(_get_name)

    def enable(self, ruleset, user = None, comment = None):
        ruleset.sources.add(self)
        ruleset.needs_test()
        ruleset.save()
        if user:
            UserAction.create(
                    action_type='enable_source',
                    comment=comment,
                    user=user,
                    source=self.source,
                    ruleset=ruleset
            )

    def disable(self, ruleset, user = None, comment = None):
        ruleset.sources.remove(self)
        ruleset.needs_test()
        ruleset.save()
        if user:
            UserAction.create(
                    action_type='disable_source',
                    comment=comment,
                    user=user,
                    source=self.source,
                    ruleset=ruleset
            )

    def export_files(self, directory):
        self.source.export_files(directory, self.version)

    def to_buffer(self):
        categories = Category.objects.filter(source = self.source)
        rules = Rule.objects.filter(category__in = categories)
        file_content = "# Rules file for " + self.name + " generated by Scirius at " + unicode(timezone.now()) + "\n"
        rules_content = [ rule.content for rule in rules ]
        file_content += "\n".join(rules_content)
        return file_content


    def test_rule_buffer(self, rule_buffer, single = False):
        testor = TestRules()
        tmpdir = tempfile.mkdtemp()
        self.export_files(tmpdir)
        related_files = {}
        for root, _, files in os.walk(tmpdir):
            for f in files:
                fullpath = os.path.join(root, f)
                if os.path.getsize(fullpath) < 50 * 1024:
                    with open(fullpath, 'r') as cf:
                        related_files[f] = cf.read()
        shutil.rmtree(tmpdir)
        if single:
            return testor.rule(rule_buffer, related_files = related_files)
        else:
            return testor.rules(rule_buffer, related_files = related_files)

    def test(self):
        rule_buffer = self.to_buffer()
        return self.test_rule_buffer(rule_buffer)

class SourceUpdate(models.Model):
    source = models.ForeignKey(Source)
    created_date = models.DateTimeField('date of update', blank = True, default = timezone.now)
    # Store update info as a JSON document
    data = models.TextField()
    version = models.CharField(max_length=42)
    changed = models.IntegerField(default=0)

    def diff(self):
        data = json.loads(self.data)
        diff = data
        diff['stats'] = {'updated':len(data['updated']), 'added':len(data['added']), 'deleted':len(data['deleted'])}
        diff['date'] = self.created_date
        return diff

    def get_absolute_url(self):
        from django.core.urlresolvers import reverse
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

    @unique
    class SuppressTransforType(TransfoType):
        SUPPRESSED = 'suppressed'

    class Meta:
        abstract = True

    # Keys
    ACTION = Type.ACTION
    LATERAL = Type.LATERAL
    TARGET = Type.TARGET
    SUPPRESSED = Type.SUPPRESSED

    # Suppression value(s)
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
        rule_ids = rule_idstools.parse(content)

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
                return rule_ids.format().encode("utf-8")
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
                self._set_target(rule_ids, target='src_ip')
                return rule_ids.format().encode("utf-8")
            elif value == Transformation.T_DESTINATION:
                self._set_target(rule_ids, target='dest_ip')
                return rule_ids.format().encode("utf-8")
            elif value == Transformation.T_AUTO:
                target_client = False
                for meta in rule_ids.metadata:
                    if meta.startswith("attack_target"):
                        target_client = True
                        break

                # not satisfactory but doing the best we can not too miss something like
                # a successful bruteforce
                if rule_ids.classtype == "attempted-recon":
                    target_client = True
                if rule_ids.classtype == "not-suspicious":
                    target_client = False
                if target_client is True:
                    self._apply_target_trans(rule_ids)

        return rule_ids.format().encode("utf-8")


class Cache:
    TRANSFORMATIONS = None

    def __init__(self):
        pass

    @classmethod
    def enable_cache(cls):
        if cls.TRANSFORMATIONS is None:
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
                                ruletransformation__value=A_DROP.value).values_list('pk', flat=True)
            reject_rules = Rule.objects.filter(
                                ruletransformation__key=ACTION.value,
                                ruletransformation__value=A_REJECT.value).values_list('pk', flat=True)
            filestore_rules = Rule.objects.filter(
                                ruletransformation__key=ACTION.value,
                                ruletransformation__value=A_FILESTORE.value).values_list('pk', flat=True)
            none_rules = Rule.objects.filter(
                                ruletransformation__key=ACTION.value,
                                ruletransformation__value=A_NONE.value).values_list('pk', flat=True)
            bypass_rules = Rule.objects.filter(
                                ruletransformation__key=ACTION.value,
                                ruletransformation__value=A_BYPASS.value).values_list('pk', flat=True)
            # Lateral
            rule_l_auto = Rule.objects.filter(
                                ruletransformation__key=LATERAL.value,
                                ruletransformation__value=L_AUTO.value).values_list('pk', flat=True)
            rule_l_yes = Rule.objects.filter(
                                ruletransformation__key=LATERAL.value,
                                ruletransformation__value=L_YES.value).values_list('pk', flat=True)
            rule_l_no = Rule.objects.filter(
                                ruletransformation__key=LATERAL.value,
                                ruletransformation__value=L_NO.value).values_list('pk', flat=True)

            # Target
            rule_t_auto = Rule.objects.filter(
                                ruletransformation__key=TARGET.value,
                                ruletransformation__value=T_AUTO.value).values_list('pk', flat=True)
            rule_t_src = Rule.objects.filter(
                                ruletransformation__key=TARGET.value,
                                ruletransformation__value=T_SOURCE.value).values_list('pk', flat=True)
            rule_t_dst = Rule.objects.filter(
                                ruletransformation__key=TARGET.value,
                                ruletransformation__value=T_DST.value).values_list('pk', flat=True)
            rule_t_none = Rule.objects.filter(
                                ruletransformation__key=TARGET.value,
                                ruletransformation__value=T_NONE.value).values_list('pk', flat=True)

            # #### Categories
            # Actions
            drop_cats = Category.objects.filter(
                                categorytransformation__key=ACTION.value,
                                categorytransformation__value=A_DROP.value).values_list('pk', flat=True)
            reject_cats = Category.objects.filter(
                                categorytransformation__key=ACTION.value,
                                categorytransformation__value=A_REJECT.value).values_list('pk', flat=True)
            filestore_cats = Category.objects.filter(
                                categorytransformation__key=ACTION.value,
                                categorytransformation__value=A_FILESTORE.value).values_list('pk', flat=True)
            none_cats = Category.objects.filter(
                                categorytransformation__key=ACTION.value,
                                categorytransformation__value=A_NONE.value).values_list('pk', flat=True)
            bypass_cats = Category.objects.filter(
                                categorytransformation__key=ACTION.value,
                                categorytransformation__value=A_BYPASS.value).values_list('pk', flat=True)

            # Lateral
            cat_l_auto = Category.objects.filter(
                                categorytransformation__key=LATERAL.value,
                                categorytransformation__value=L_AUTO.value).values_list('pk', flat=True)
            cat_l_yes = Category.objects.filter(
                                categorytransformation__key=LATERAL.value,
                                categorytransformation__value=L_YES.value).values_list('pk', flat=True)
            cat_l_no = Category.objects.filter(
                                categorytransformation__key=LATERAL.value,
                                categorytransformation__value=L_NO.value).values_list('pk', flat=True)
            # Target
            cat_t_auto = Category.objects.filter(
                                categorytransformation__key=TARGET.value,
                                categorytransformation__value=T_AUTO.value).values_list('pk', flat=True)
            cat_t_src = Category.objects.filter(
                                categorytransformation__key=TARGET.value,
                                categorytransformation__value=T_SOURCE.value).values_list('pk', flat=True)
            cat_t_dst = Category.objects.filter(
                                categorytransformation__key=TARGET.value,
                                categorytransformation__value=T_DST.value).values_list('pk', flat=True)
            cat_t_none = Category.objects.filter(
                                categorytransformation__key=TARGET.value,
                                categorytransformation__value=T_NONE.value).values_list('pk', flat=True)

            # #### Rulesets
            # Actions
            drop_rulesets = Ruleset.objects.filter(
                                rulesettransformation__key=ACTION.value,
                                rulesettransformation__value=A_DROP.value).values_list('pk', flat=True)
            reject_rulesets = Ruleset.objects.filter(
                                rulesettransformation__key=ACTION.value,
                                rulesettransformation__value=A_REJECT.value).values_list('pk', flat=True)
            filestore_rulesets = Ruleset.objects.filter(
                                rulesettransformation__key=ACTION.value,
                                rulesettransformation__value=A_FILESTORE.value).values_list('pk', flat=True)
            bypass_rulesets = Ruleset.objects.filter(
                                rulesettransformation__key=ACTION.value,
                                rulesettransformation__value=A_BYPASS.value).values_list('pk', flat=True)

            # Lateral
            ruleset_l_auto = Ruleset.objects.filter(
                                rulesettransformation__key=LATERAL.value,
                                rulesettransformation__value=L_AUTO.value).values_list('pk', flat=True)
            ruleset_l_yes = Ruleset.objects.filter(
                                rulesettransformation__key=LATERAL.value,
                                rulesettransformation__value=L_YES.value).values_list('pk', flat=True)
            # Target
            ruleset_t_auto = Ruleset.objects.filter(
                                rulesettransformation__key=TARGET.value,
                                rulesettransformation__value=T_AUTO.value).values_list('pk', flat=True)
            ruleset_t_src = Ruleset.objects.filter(
                                rulesettransformation__key=TARGET.value,
                                rulesettransformation__value=T_SOURCE.value).values_list('pk', flat=True)
            ruleset_t_dst = Ruleset.objects.filter(
                                rulesettransformation__key=TARGET.value,
                                rulesettransformation__value=T_DST.value).values_list('pk', flat=True)

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
        if cls.TRANSFORMATIONS is not None:
            del cls.TRANSFORMATIONS
            cls.TRANSFORMATIONS = None
        else:
            raise Exception("%s cache has not been open" % cls.__name__)


class Category(models.Model, Transformable, Cache):
    name = models.CharField(max_length=100)
    filename = models.CharField(max_length=200)
    descr = models.CharField(max_length=400, blank = True)
    created_date = models.DateTimeField('date created', default = timezone.now)
    source = models.ForeignKey(Source)

    class Meta:
        verbose_name_plural = "categories"

    def __unicode__(self):
        return self.name

    def __init__(self, *args, **kwargs):
        models.Model.__init__(self, *args, **kwargs)
        Cache.__init__(self)

    @staticmethod
    def get_icon():
        return 'fa-list-alt'

    def build_sigs_group(self):
        # query sigs with group set
        rules = Rule.objects.filter(group = True, category = self)
        sigs_groups = {}
        # build hash on message
        for rule in rules:
            # let's get the new IP only, will output that as text field at save time
            rule.ips_list = set()
            sigs_groups[rule.msg] = rule
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
        # TODO hand idstools parsing errors
        rule = rule_idstools.parse(line)
        rule_base_msg = Rule.GROUPSNAMEREGEXP.findall(rule.msg)[0]
        # check if we already have a signature in the group signatures
        # that match
        if rule_base_msg in sigs_groups:
            # TODO coherence check
            # add IPs to the list if revision has changed
            if rule.rev != sigs_groups[rule_base_msg].rev:
                self.parse_group_signature(sigs_groups[rule_base_msg], rule)
                # Is there an existing rule to clean ? this is needed at
                # conversion of source to use iprep but we will have a different
                # message in this case (with group)
                if existing_rules_hash.has_key(rule.sid):
                    # the sig is already present and it is a group sid so let's declare it
                    # updated to avoid its deletion later in process. No else clause because
                    # the signature will be deleted as it is not referenced in a changed or
                    # unchanged list
                    if rule_base_msg == existing_rules_hash[rule.sid].msg:
                        rules_update["updated"].append(existing_rules_hash[rule.sid])
            else:
                rules_unchanged.append(sigs_groups[rule_base_msg])
        else:
            creation_date = timezone.now()
            state = True
            if rule.raw.startswith("#"):
                state = False
            # update rule content
            content = rule.raw
            iprep_group = rule.sid
            ips_list = Rule.IPSREGEXP['src'].findall(rule.header)[0]
            if ips_list.startswith('['):
                track_by = 'src'
            else:
                track_by = 'dst'
            content = content.replace(';)','; iprep:%s,%s,>,1;)' % (track_by, iprep_group))
            # replace IP list by any
            content = re.sub(r'\[\d+.*\d+\]', r'any', content)
            # fix message
            content = re.sub(r'msg:".*";', r'msg:"%s";' % rule_base_msg, content)
            # if we already have a signature with the SID we are probably parsing
            # a source that has just been switched to iprep. So we get the old
            # rule and we update the content to avoid loosing information.
            if existing_rules_hash.has_key(rule.sid):
                group_rule = existing_rules_hash[rule.sid]
                group_rule.group = True
                group_rule.msg = rule_base_msg
                group_rule.content = content
                group_rule.updated_date = creation_date
                group_rule.rev = rule.rev
                rules_update["updated"].append(group_rule)
            else:
                group_rule = Rule(category = self, sid = rule.sid, group = True,
                        rev = rule.rev - 1, content = content, msg = rule_base_msg,
                        state_in_source = state, state = state,
                        imported_date = creation_date, updated_date = creation_date)
                rules_update["updated"].append(group_rule)
                group_rule.parse_metadata()
                group_rule.parse_flowbits(source, flowbits, addition = True)
            if track_by == 'src':
                group_rule.group_by = 'by_src'
            else:
                group_rule.group_by = 'by_dest'
            group_rule.ips_list = set()
            self.parse_group_signature(group_rule, rule)
            sigs_groups[group_rule.msg] = group_rule

    def get_rules(self, source, existing_rules_hash=None):
        # parse file
        # return an object with updates
        getsid = re.compile("sid *: *(\d+)")
        getrev = re.compile("rev *: *(\d+)")
        getmsg = re.compile("msg *: *\"(.*?)\"")
        source_git_dir = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.source.pk))
        rfile = open(os.path.join(source_git_dir, self.filename))

        rules_update = {"added": [], "deleted": [], "updated": []}
        rules_unchanged = []

        if existing_rules_hash == None:
            existing_rules_hash = {}
            for rule in Rule.objects.all().prefetch_related('category'):
                existing_rules_hash[rule.sid] = rule
        rules_list = []
        for rule in Rule.objects.filter(category = self):
            rules_list.append(rule)

        flowbits = { 'added': {'flowbit': [], 'through_set': [], 'through_isset': [] }}
        existing_flowbits = Flowbit.objects.all().order_by('-pk')
        if len(existing_flowbits):
            flowbits['last_pk'] = existing_flowbits[0].pk
        else:
            flowbits['last_pk'] = 1
        for key in ('flowbits', 'hostbits', 'xbits'):
            flowbits[key] = {}
            for flowb in Flowbit.objects.filter(source=source, type=key):
                flowbits[key][flowb.name] = flowb

        creation_date = timezone.now()

        rules_groups = {}
        if source.use_iprep:
            rules_groups = self.build_sigs_group()

        with transaction.atomic():
            for line in rfile.readlines():
                line = line.decode('utf-8')
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
                sid = match.groups()[0]
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

                if source.use_iprep and Rule.GROUPSNAMEREGEXP.match(msg):
                    self.add_group_signature(rules_groups, line, existing_rules_hash, source, flowbits, rules_update, rules_unchanged)
                else:
                    if existing_rules_hash.has_key(int(sid)):
                        # FIXME update references if needed
                        rule = existing_rules_hash[int(sid)]
                        if rule.category.source != source:
                            raise ValidationError('Duplicate SID: %d' % (int(sid)))
                        if rev == None or rule.rev < rev or rule.group is True:
                            rule.content = line
                            if rev == None:
                                rule.rev = 0
                            else:
                                rule.rev = rev
                            if rule.category != self:
                                rule.category = self
                            rule.msg = msg
                            rules_update["updated"].append(rule)
                            rule.updated_date = creation_date
                            rule.parse_metadata()
                            rule.save()
                            rule.parse_flowbits(source, flowbits)
                        else:
                            rules_unchanged.append(rule)
                    else:
                        if rev == None:
                            rev = 0
                        rule = Rule(category = self, sid = sid,
                                            rev = rev, content = line, msg = msg,
                                            state_in_source = state, state = state, imported_date = creation_date, updated_date = creation_date)
                        rule.parse_metadata()
                        rules_update["added"].append(rule)
                        rule.parse_flowbits(source, flowbits, addition = True)
            if len(rules_update["added"]):
                Rule.objects.bulk_create(rules_update["added"])
            if len(rules_groups):
                for rule in rules_groups:
                    # If IP list is empty it will be deleted because it has not
                    # been put in a changed or unchanged list. So we just care
                    # about saving the rule.
                    if len(rules_groups[rule].ips_list) > 0:
                        rules_groups[rule].group_ips_list = ",".join(rules_groups[rule].ips_list)
                        rules_groups[rule].rev = rules_groups[rule].next_rev
                        rules_groups[rule].save()
            if len(flowbits["added"]["flowbit"]):
                Flowbit.objects.bulk_create(flowbits["added"]["flowbit"])
            if len(flowbits["added"]["through_set"]):
                Flowbit.set.through.objects.bulk_create(flowbits["added"]["through_set"])
            if len(flowbits["added"]["through_isset"]):
                Flowbit.isset.through.objects.bulk_create(flowbits["added"]["through_isset"])
            rules_update["deleted"] = list(set(rules_list) -
                                      set(rules_update["added"]).union(set(rules_update["updated"])) -
                                      set(rules_unchanged))
            source.aggregate_update(rules_update)

    def get_absolute_url(self):
        from django.core.urlresolvers import reverse
        return reverse('category', args=[str(self.id)])

    def enable(self, ruleset, user = None, comment = None):
        ruleset.categories.add(self)
        ruleset.needs_test()
        ruleset.save()
        if user:
            UserAction.create(
                    action_type='enable_category',
                    comment=comment,
                    user=user,
                    category=self,
                    ruleset=ruleset
            )

    def disable(self, ruleset, user = None, comment = None):
        ruleset.categories.remove(self)
        ruleset.needs_test()
        ruleset.save()
        if user:
            UserAction.create(
                    action_type='disable_category',
                    comment=comment,
                    user=user,
                    category=self,
                    ruleset=ruleset
            )

    def is_transformed(self, ruleset, key=Transformation.ACTION, value=Transformation.A_DROP):
        if Category.TRANSFORMATIONS is None:
            return (self.pk in ruleset.get_transformed_categories(key=key, value=value).values_list('pk', flat=True))

        category_str = Category.__name__.lower()
        return (self.pk in Category.TRANSFORMATIONS[key][category_str][value])

    def suppress_transformation(self, ruleset, key):
        CategoryTransformation.objects.filter(
                ruleset=ruleset,
                category_transformation=self,
                key=key.value).delete()

    def toggle_transformation(self, ruleset, key=Transformation.ACTION, value=Transformation.A_DROP):
        if self.is_transformed(ruleset, key=key, value=value):
            CategoryTransformation.objects.filter(
                    ruleset=ruleset,
                    category_transformation=self,
                    key=key.value).delete()
        else:
            c = CategoryTransformation(
                    ruleset=ruleset,
                    category_transformation=self,
                    key=key.value,
                    value=value.value)
            c.save()
        ruleset.needs_test()

    def get_transformation(self, ruleset, key=Transformation.ACTION, override=False):
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

        if Category.TRANSFORMATIONS is None:
            ct = CategoryTransformation.objects.filter(
                                    key=key.value,
                                    ruleset=ruleset,
                                    category_transformation=self)
            if len(ct) > 0:
                return TYPE(ct[0].value)

            if override:
                rt = RulesetTransformation.objects.filter(
                                    key=key.value,
                                    ruleset_transformation=ruleset)
                if len(rt) > 0:
                    return TYPE(rt[0].value)

        else:
            category_str = Category.__name__.lower()
            ruleset_str = Ruleset.__name__.lower()

            for trans, tsets in Category.TRANSFORMATIONS[key][category_str].iteritems():
                if self.pk in tsets:  # DROP / REJECT / FILESTORE / NONE
                    return trans

            if override:
                for trans, tsets in Rule.TRANSFORMATIONS[key][ruleset_str].iteritems():
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
    GROUP_BY_CHOICES= (('by_src', 'by_src'),('by_dst', 'by_dst'))
    sid = models.IntegerField(primary_key=True)
    category = models.ForeignKey(Category)
    msg = models.CharField(max_length=1000)
    state = models.BooleanField(default=True)
    state_in_source = models.BooleanField(default=True)
    rev = models.IntegerField(default=0)
    content = models.CharField(max_length=10000)
    imported_date = models.DateTimeField(default = timezone.now)
    updated_date = models.DateTimeField(default = timezone.now)
    created = models.DateField(blank = True, null = True)
    updated = models.DateField(blank = True, null = True)
    group = models.BooleanField(default = False)
    group_by = models.CharField(max_length = 10, choices = GROUP_BY_CHOICES, default='by_src')
    group_ips_list = models.TextField(blank = True, null = True)  # store one IP per line

    hits = 0

    BITSREGEXP = {'flowbits': re.compile("flowbits *: *(isset|set),(.*?) *;"),
                  'hostbits': re.compile("hostbits *: *(isset|set),(.*?) *;"),
                  'xbits': re.compile("xbits *: *(isset|set),(.*?) *;"),
                 }

    IPSREGEXP = {'src': re.compile('^\S+ +\S+ (.*) +\S+ +\->'), 'dest': re.compile('\-> (.*) +\S+$')}

    GROUPSNAMEREGEXP = re.compile('^(.*) +group +\d+$')

    def __unicode__(self):
        return str(self.sid) + ":" + self.msg

    def __init__(self, *args, **kwargs):
        models.Model.__init__(self, *args, **kwargs)
        Cache.__init__(self)

    @staticmethod
    def get_icon():
        return 'fa-shield'

    def get_absolute_url(self):
        from django.core.urlresolvers import reverse
        return reverse('rule', args=[str(self.sid)])

    def parse_flowbits(self, source, flowbits, addition = False):
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
                    if not flowinst[1] in flowbits[ftype].keys():
                        elt = Flowbit(type = ftype, name = flowinst[1],
                                      source = source)
                        flowbits['last_pk'] += 1
                        elt.id = flowbits['last_pk']
                        flowbits[ftype][flowinst[1]] = elt
                        flowbits['added']['flowbit'].append(elt)
                    else:
                        elt = flowbits[ftype][flowinst[1]]

                    if flowinst[0] == "isset":
                        if addition or not self.checker.filter(isset=self):
                            through_elt = Flowbit.isset.through(flowbit=elt, rule=self)
                            flowbits['added']['through_isset'].append(through_elt)
                    else:
                        if addition or not self.setter.filter(set=self):
                            through_elt = Flowbit.set.through(flowbit=elt, rule=self)
                            flowbits['added']['through_set'].append(through_elt)

    def parse_metadata_time(self, sfield):
        sdate = sfield.split(' ')[1]
        if sdate:
            de = sdate.split('_')
            try:
                return datetime_date(int(de[0]),int(de[1]),int(de[2]))
            except ValueError:
                # Catches conversion to int failure, in case the date is 'unknown'
                pass

        return None

    def parse_metadata(self):
        rule_ids = rule_idstools.parse(self.content)
        if rule_ids is None:
            return
        for meta in rule_ids.metadata:
            if meta.startswith('created_at '):
                self.created = self.parse_metadata_time(meta)
            if meta.startswith('updated_at '):
                self.updated = self.parse_metadata_time(meta)

    def is_active(self, ruleset):
        SUPPRESSED = Transformation.SUPPRESSED
        S_SUPPRESSED = Transformation.S_SUPPRESSED
        if self.state and self.category in ruleset.categories.all() and self not in ruleset.get_transformed_rules(key=SUPPRESSED, value=S_SUPPRESSED):
            return True
        return False

    # flowbit dependency:
    # if we disable a rule that is the last one set a flag then we must disable all the 
    # dependant rules
    def get_dependant_rules(self, ruleset):
        # get list of flowbit we are setting
        flowbits_list = Flowbit.objects.filter(set = self).prefetch_related('set', 'isset')
        dependant_rules = []
        for flowbit in flowbits_list:
            set_count = 0
            for rule in flowbit.set.all():
                if rule == self:
                    continue
                if rule.is_active(ruleset):
                    set_count += 1
            if set_count == 0:
                dependant_rules.extend(list(flowbit.isset.all()))
                # we need to recurse if ever we did disable in a chain of signatures
                for drule in flowbit.isset.all():
                    dependant_rules.extend(drule.get_dependant_rules(ruleset))
        return dependant_rules

    def get_actions(self):
        uas = UserAction.objects.filter(
                user_action_objects__content_type=ContentType.objects.get_for_model(Rule),
                user_action_objects__object_id=self.pk).order_by('-date')
        return uas

    def get_comments(self):
        uas = UserAction.objects.filter(
                action_type__in=['comment_rule', 'transform_rule', 'enable_rule', 'suppress_rule', 'disable_rule', 'delete_suppress_rule'],
                user_action_objects__content_type=ContentType.objects.get_for_model(Rule),
                user_action_objects__object_id=self.pk).order_by('-date')
        return uas

    def enable(self, ruleset, user = None, comment = None):
        enable_rules = [self]
        enable_rules.extend(self.get_dependant_rules(ruleset))
        ruleset.enable_rules(enable_rules)
        if user:
            UserAction.create(
                    action_type='enable_rule',
                    comment=comment,
                    user=user,
                    rule=self,
                    ruleset=ruleset
            )
        return

    def disable(self, ruleset, user = None, comment = None):
        disable_rules = [self]
        disable_rules.extend(self.get_dependant_rules(ruleset))
        ruleset.disable_rules(disable_rules)
        if user:
            UserAction.create(
                    action_type='disable_rule',
                    comment=comment,
                    user=user,
                    rule=self,
                    ruleset=ruleset
            )
        return

    def test(self, ruleset):
        self.enable_cache()
        try:
            test = ruleset.test_rule_buffer(self.generate_content(ruleset), single = True)
            self.disable_cache()
            return test
        except:
            self.disable_cache()
        return False

    def toggle_availability(self):
        self.category.source.needs_test()
        self.state = not self.state
        self.save()

    def apply_transformation(self, content, key=Transformation.ACTION, value=None):

        if key == Transformation.ACTION:
            if value == Transformation.A_REJECT:
                content = re.sub("^ *\S+", "reject", content)
            elif value == Transformation.A_DROP:
                content = re.sub("^ *\S+", "drop", content)
            elif value == Transformation.A_FILESTORE:
                content = re.sub("; *\)", "; filestore;)", content)
            elif value == Transformation.A_BYPASS:
                if 'noalert' in content:
                    content = re.sub("; noalert;", "; noalert; bypass;", content)
                else:
                    content = re.sub("; *\)", "; noalert; bypass;)", content)
                content = re.sub("^ *\S+", "pass", content)

        elif key == Transformation.LATERAL or key == Transformation.TARGET:
            content = self.apply_lateral_target_transfo(content, key, value)

        return content

    def can_drop(self):
        return "noalert" not in self.content

    def can_filestore(self):
        return self.content.split(' ')[1] in ('http', 'smtp', 'smb', 'nfs')

    def can_lateral(self, value):
        content = self.content.encode('utf8')
        rule_ids = rule_idstools.parse(self.content)

        # Workaround: ref #674
        # Cannot transform, idstools cannot parse it
        # So remove this transformation from choices
        if rule_ids is None or 'outbound' in rule_ids['msg'].lower():
            return False

        if '$EXTERNAL_NET' in rule_ids.raw:
            return True

        return False

    def can_target(self):
        rule_ids = rule_idstools.parse(self.content)
        return (rule_ids is not None)

    def is_transformed(self, ruleset, key=Transformation.ACTION, value=Transformation.A_DROP):
        if Rule.TRANSFORMATIONS is None:
            return (self in ruleset.get_transformed_rules(key=key, value=value).values_list('pk', flat=True))

        rule_str = Rule.__name__.lower()
        return (self.pk in Rule.TRANSFORMATIONS[key][rule_str][value])

    def get_transformation(self, ruleset, key=Transformation.ACTION, override=False):
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

        if Rule.TRANSFORMATIONS is None:
            rt = RuleTransformation.objects.filter(
                                key=key.value,
                                ruleset=ruleset,
                                rule_transformation=self).all()
            if len(rt) > 0:
                return TYPE(rt[0].value)

            if override:
                ct = CategoryTransformation.objects.filter(
                                        key=key.value,
                                        ruleset=ruleset,
                                        category_transformation=self.category).all()
                if len(ct) > 0:
                    return TYPE(ct[0].value)

                rt = RulesetTransformation.objects.filter(
                                    key=key.value,
                                    ruleset_transformation=ruleset)
                if len(rt) > 0:
                    return TYPE(rt[0].value)

        else:
            rule_str = Rule.__name__.lower()
            category_str = Category.__name__.lower()
            ruleset_str = Ruleset.__name__.lower()

            for trans, tsets in Rule.TRANSFORMATIONS[key][rule_str].iteritems():
                if self.pk in tsets:
                    return trans

            if override:
                for trans, tsets in Rule.TRANSFORMATIONS[key][category_str].iteritems():
                    if self.category.pk in tsets:
                        return trans

                for trans, tsets in Rule.TRANSFORMATIONS[key][ruleset_str].iteritems():
                    if ruleset.pk in tsets:
                        return trans

        return None

    def remove_transformations(self, ruleset, key):
        RuleTransformation.objects.filter(
                ruleset=ruleset,
                rule_transformation=self,
                key=key.value).delete()

        ruleset.needs_test()
        ruleset.save()

    def set_transformation(self, ruleset, key=Transformation.ACTION, value=Transformation.A_DROP):
        self.remove_transformations(ruleset, key)

        r = RuleTransformation(
                ruleset=ruleset,
                rule_transformation=self,
                key=key.value,
                value=value.value)
        r.save()

        ruleset.needs_test()
        ruleset.save()

    def generate_content(self, ruleset):
        content = self.content

        # explicitely set prio on transformation here
        # Action
        ACTION = Transformation.ACTION
        A_DROP = Transformation.A_DROP
        A_FILESTORE = Transformation.A_FILESTORE
        A_REJECT = Transformation.A_REJECT
        A_BYPASS = Transformation.A_BYPASS

        trans = self.get_transformation(key=ACTION, ruleset=ruleset, override=True)
        if (trans in (A_DROP, A_REJECT) and self.can_drop()) or \
                (trans == A_FILESTORE and self.can_filestore()) or \
                (trans == A_BYPASS):
            content = self.apply_transformation(content, key=Transformation.ACTION, value=trans)

        # Lateral
        LATERAL = Transformation.LATERAL
        L_AUTO = Transformation.L_AUTO
        L_YES = Transformation.L_YES

        trans = self.get_transformation(key=LATERAL, ruleset=ruleset, override=True)
        if trans in (L_YES, L_AUTO) and self.can_lateral(trans):
            content = self.apply_transformation(content, key=Transformation.LATERAL, value=trans)

        # Target
        TARGET = Transformation.TARGET
        T_SOURCE = Transformation.T_SOURCE
        T_DESTINATION = Transformation.T_DESTINATION
        T_AUTO = Transformation.T_AUTO

        trans = self.get_transformation(key=TARGET, ruleset=ruleset, override=True)
        if trans in (T_SOURCE, T_DESTINATION, T_AUTO):
            c = content
            if isinstance(content, unicode):
                c = content.encode('utf8')
            content = self.apply_transformation(c, key=Transformation.TARGET, value=trans)

        if isinstance(content, str):
            content = content.decode('utf8')

        return content

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

        if key == TARGET:
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

        if key == LATERAL:
            RULESET_DEFAULT = Transformation.L_RULESET_DEFAULT

            allowed_choices = list(Transformation.LateralTransfoType.get_choices())
            allowed_choices.remove((RULESET_DEFAULT.value, RULESET_DEFAULT.name.replace('_', ' ').title()))

            L_YES = Transformation.L_YES
            L_AUTO = Transformation.L_AUTO

            for trans in (L_YES, L_AUTO):
                if not self.can_lateral(trans):
                    allowed_choices.remove((trans.value, trans.name.title()))

        return tuple(allowed_choices)

def build_iprep_name(msg):
    return re.sub('[^0-9a-zA-Z]+', '_', msg.replace(' ',''))

class Flowbit(models.Model):
    FLOWBIT_TYPE = (('flowbits', 'Flowbits'), ('hostbits', 'Hostbits'), ('xbits', 'Xbits'))
    type = models.CharField(max_length=12, choices=FLOWBIT_TYPE)
    name = models.CharField(max_length=100)
    set = models.ManyToManyField(Rule, related_name='setter')
    isset = models.ManyToManyField(Rule, related_name='checker')
    enable = models.BooleanField(default=True)
    source = models.ForeignKey(Source)


# we should use django reversion to keep track of this one
# even if fixing HEAD may be complicated
class Ruleset(models.Model, Transformable):
    name = models.CharField(max_length=100, unique = True)
    descr = models.CharField(max_length=400, blank = True)
    created_date = models.DateTimeField('date created')
    updated_date = models.DateTimeField('date updated', blank = True)
    need_test = models.BooleanField(default=True)
    validity = models.BooleanField(default=True)
    errors = models.TextField(blank = True)
    rules_count = models.IntegerField(default=0)

    editable = True

    # List of Source that can be used in the ruleset
    # It can be a specific version or HEAD if we want to use
    # latest available
    sources = models.ManyToManyField(SourceAtVersion)
    # List of Category selected in the ruleset
    categories = models.ManyToManyField(Category, blank=True)
    rules_transformation = models.ManyToManyField(Rule, through='RuleTransformation', related_name='rules_transformed', blank=True)
    categories_transformation = models.ManyToManyField(Category, through='CategoryTransformation', related_name='categories_transformed', blank=True)


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

    def __unicode__(self):
        return self.name

    def _json_errors(self):
        return json.loads(self.errors)

    json_errors = property(_json_errors)

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

            L_YES = Transformation.L_YES
            L_AUTO = Transformation.L_AUTO

        return tuple(allowed_choices)

    @staticmethod
    def get_icon():
        return 'fa-list-alt'

    def remove_transformation(self, key):
        RulesetTransformation.objects.filter(
                ruleset_transformation=self,
                key=key.value).delete()

        self.needs_test()
        self.save()

    def set_transformation(self, key=Transformation.ACTION, value=Transformation.A_DROP):
        self.remove_transformation(key)

        r = RulesetTransformation(
                ruleset_transformation=self,
                key=key.value,
                value=value.value)
        r.save()

        self.needs_test()
        self.save()

    def get_transformed_categories(self,
                                   key=Transformation.ACTION,
                                   value=Transformation.A_DROP,
                                   excludes=[],
                                   order_by=None):

        # All transformed categories from this ruleset
        if key is None:
            return Category.objects.filter(categorytransformation__ruleset=self)

        categories = Category.objects.filter(
                            categorytransformation__ruleset=self,
                            categorytransformation__key=key.value,
                            categorytransformation__value=value.value)

        if order_by is not None:
            categories = categories.order_by(order_by)

        if excludes is not None:
            if isinstance(excludes, (list, tuple, set)):
                for exclude in excludes:
                    categories = categories.exclude(pk__in=exclude)
            elif isinstance(excludes, (str, unicode)):
                categories = categories.exclude(pk__in=excludes)

        return categories

    def get_transformed_rules(self,
                              key=Transformation.ACTION,
                              value=Transformation.A_DROP,
                              excludes=[],
                              order_by=None):

        # All transformed rules from this ruleset
        if key is None:
            return Rule.objects.filter(ruletransformation__ruleset=self)

        rules = Rule.objects.filter(
                            ruletransformation__ruleset=self,
                            ruletransformation__key=key.value,
                            ruletransformation__value=value.value)

        if order_by is not None:
            rules = rules.order_by(order_by)

        if excludes is not None:
            if isinstance(excludes, (list, tuple, set)):
                for exclude in excludes:
                    rules = rules.exclude(pk__in=exclude)
            elif isinstance(excludes, (str, unicode)):
                rules = rules.exclude(pk__in=excludes)

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
                                ruleset_transformation=self).exclude(value=NONE.value)
        if len(rt) > 0:
            return TYPE(rt[0].value)

        return None

    def is_transformed(self, key=Transformation.ACTION, value=Transformation.A_DROP):
        ruleset_str = Ruleset.__name__.lower()
        rulesets_t = Ruleset.objects.filter(
                rulesettransformation__key=key.value,
                rulesettransformation__value=value.value)

        return (self.pk in rulesets_t.values_list('pk', flat=True))

    def get_absolute_url(self):
        from django.core.urlresolvers import reverse
        return reverse('ruleset', args=[str(self.id)])

    def update(self):
        sourcesatversion = self.sources.all()
        for sourcesat in sourcesatversion:
            sourcesat.source.update()
        self.updated_date = timezone.now()
        self.need_test = True
        self.save()

    def generate(self):
        # TODO: manage other types
        S_SUPPRESSED = Transformation.S_SUPPRESSED

        rules = Rule.objects.select_related('category').filter(category__in=self.categories.all(), state=True).exclude(ruletransformation__value=S_SUPPRESSED.value)
        return rules

    def generate_threshold(self, directory):
        thresholdfile = os.path.join(directory, 'threshold.config')
        with open(thresholdfile, 'w') as f:
            for threshold in Threshold.objects.filter(ruleset = self):
                f.write("%s\n" % (threshold))

            from scirius.utils import get_middleware_module
            for threshold in get_middleware_module('common').get_processing_filter_thresholds(self):
                f.write(threshold)

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
        self.sources = orig_sources
        self.categories = orig_categories
        self.save()
        for truleset in RulesetTransformation.objects.filter(ruleset_transformation_id = orig_ruleset_pk):
            truleset.ruleset_transformation = self
            truleset.pk = None
            truleset.id = None
            truleset.save()
        for threshold in Threshold.objects.filter(ruleset_id = orig_ruleset_pk):
            threshold.ruleset = self
            threshold.pk = None
            threshold.id = None
            threshold.save()
        for tcat in CategoryTransformation.objects.filter(ruleset_id = orig_ruleset_pk):
            tcat.ruleset = self
            tcat.pk = None
            tcat.id = None
            tcat.save()
        for trule in RuleTransformation.objects.filter(ruleset_id = orig_ruleset_pk):
            trule.ruleset = self
            trule.pk = None
            trule.id = None
            trule.save()
        return self

    def export_files(self, directory):
        for src in self.sources.all():
            src.export_files(directory)
        # generate threshold.config
        self.generate_threshold(directory)

    def diff(self, mode='long'):
        sourcesatversion = self.sources.all()
        sdiff = {}
        for sourceat in sourcesatversion:
            supdate = SourceUpdate.objects.filter(source = sourceat.source).order_by('-created_date')
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
        rules = self.generate()
        self.rules_count = len(rules)
        file_content = "# Rules file for " + self.name + " generated by Scirius at " + str(timezone.now()) + "\n"

        if len(rules) > 0:
            Rule.enable_cache()

            rules_content = []
            for rule in rules:
                c = rule.generate_content(self)
                if c:
                    rules_content.append(c)
            file_content += "\n".join(rules_content)

            Rule.disable_cache()

        return file_content

    def test_rule_buffer(self, rule_buffer, single = False):
        testor = TestRules()
        tmpdir = tempfile.mkdtemp()
        self.export_files(tmpdir)
        related_files = {}
        for root, _, files in os.walk(tmpdir):
            for f in files:
                fullpath = os.path.join(root, f)
                with open(fullpath, 'r') as cf:
                    related_files[f] = cf.read( 50 * 1024)
        shutil.rmtree(tmpdir)
        if single:
            return testor.rule(rule_buffer, related_files = related_files)
        else:
            return testor.rules(rule_buffer, related_files = related_files)

    def test(self):
        self.need_test = False
        rule_buffer = self.to_buffer()
        result = self.test_rule_buffer(rule_buffer)
        result['rules_count'] = self.rules_count
        self.validity = result['status']
        if result.has_key('errors'):
            self.errors = json.dumps(result['errors'])
        else:
            self.errors = json.dumps([])
        self.save()
        return result

    def disable_rules(self, rules):
        SUPPRESSED = Transformation.SUPPRESSED
        S_SUPPRESSED = Transformation.S_SUPPRESSED

        rts = []
        suppressed_rules = self.get_transformed_rules(key=SUPPRESSED, value=S_SUPPRESSED).values_list('pk', flat=True)
        for rule in rules:
            if rule.pk not in suppressed_rules:
                rt = RuleTransformation(
                        ruleset=self,
                        rule_transformation=rule,
                        key=SUPPRESSED.value,
                        value=S_SUPPRESSED.value)
                rts.append(rt)

        RuleTransformation.objects.bulk_create(rts)
        self.needs_test()

    def enable_rules(self, rules):
        SUPPRESSED = Transformation.SUPPRESSED
        S_SUPPRESSED = Transformation.S_SUPPRESSED

        RuleTransformation.objects.filter(
                        ruleset=self,
                        rule_transformation__in=rules,
                        key=SUPPRESSED.value,
                        value=S_SUPPRESSED.value).delete()
        self.needs_test()

    def needs_test(self):
        self.need_test = True
        self.save()


class RuleTransformation(Transformation):
    ruleset = models.ForeignKey(Ruleset)
    rule_transformation = models.ForeignKey(Rule)

    class Meta:
        unique_together = ('ruleset', 'rule_transformation', 'key')


class CategoryTransformation(Transformation):
    ruleset = models.ForeignKey(Ruleset)
    category_transformation = models.ForeignKey(Category)

    class Meta:
        unique_together = ('ruleset', 'category_transformation', 'key')


class RulesetTransformation(Transformation):
    ruleset_transformation = models.ForeignKey(Ruleset, on_delete=models.CASCADE)

    class Meta:
        unique_together = ('ruleset_transformation', 'key')


class Threshold(models.Model):
    THRESHOLD_TYPES = (('threshold', 'threshold'), ('suppress', 'suppress'))
    THRESHOLD_TYPE_TYPES = (('limit', 'limit'), ('threshold', 'threshold'), ('both', 'both'))
    TRACK_BY_CHOICES= (('by_src', 'by_src'),('by_dst', 'by_dst'))
    descr = models.CharField(max_length=400, blank = True)
    threshold_type = models.CharField(max_length=20, choices=THRESHOLD_TYPES, default='suppress')
    type = models.CharField(max_length=20, choices=THRESHOLD_TYPE_TYPES, default='limit')
    gid = models.IntegerField(default=1)
    rule = models.ForeignKey(Rule, default = None)
    ruleset = models.ForeignKey(Ruleset, default = None)
    track_by = models.CharField(max_length= 10, choices = TRACK_BY_CHOICES, default='by_src')
    net = models.CharField(max_length=100, blank = True)
    count = models.IntegerField(default=1)
    seconds = models.IntegerField(default=60)

    def __unicode__(self):
        rep = ""
        if self.threshold_type == "suppress":
            rep = "suppress gen_id %d, sig_id %d" % (self.gid, self.rule.sid)
            rep += ", track %s, ip %s" % (self.track_by, self.net)
        else:
            rep = "%s gen_id %d, sig_id %d, type %s, track %s, count %d, seconds %d" % (self.threshold_type, self.gid, self.rule.sid, self.type, self.track_by, self.count, self.seconds)
        return rep

    def get_absolute_url(self):
        from django.core.urlresolvers import reverse
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
    ACTIONS = (('suppress', 'Suppress'), ('threshold', 'Threshold'),
                ('tag', 'Tag'), ('tagkeep', 'Tag and keep'))

    action = models.CharField(max_length=10, choices=ACTIONS)
    options = models.CharField(max_length=512, null=True, blank=True)
    index = models.PositiveIntegerField()
    description = models.TextField(default='')
    enabled = models.BooleanField(default=True)
    rulesets = models.ManyToManyField(Ruleset, related_name='processing_filters')

    class Meta:
        ordering = ['index']

    def get_options(self):
        if not self.options:
            return {}
        return json.loads(self.options)

    def get_threshold_content(self):
        sid = self.filter_defs.get(key='alert.signature_id').value

        if self.action == 'suppress':
            try:
                src_ip = self.filter_defs.get(key='src_ip')
            except models.ObjectDoesNotExist:
                src_ip = None
            try:
                dest_ip = self.filter_defs.get(key='dest_ip')
            except models.ObjectDoesNotExist:
                dest_ip = None

            if src_ip:
                ip_str = src_ip.value
                track_by = 'by_src'
            else:
                ip_str = dest_ip.value
                track_by = 'by_dst'

            return 'suppress gen_id 1, sid_id %s, track %s, ip %s\n' % (sid, track_by, ip_str)
        elif self.action == 'threshold':
            options = self.get_options()
            return 'threshold gen_id 1, sig_id %s, type %s, track %s, count %s, seconds %s\n' % (sid, options['type'], options['track'], options['count'], options['seconds'])

        raise Exception('Invalid processing filter action %s' % self.action)

    @staticmethod
    def get_icon():
        return 'pficon-filter'

    def __unicode__(self):
        filters = []
        for f in self.filter_defs.order_by('key'):
            filters.append(unicode(f))
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
    proc_filter = models.ForeignKey(RuleProcessingFilter, related_name='filter_defs')

    class Meta:
        ordering = ('key', 'value')

    def __unicode__(self):
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

def export_iprep_files(target_dir):
    group_rules = Rule.objects.filter(group = True)
    cat_map = {}
    with open(target_dir + "/" + "scirius-categories.txt", 'w') as rfile:
        index = 1
        for rule in group_rules:
            rfile.write('%s,%d,%s\n' % (index, rule.sid, rule.msg))
            cat_map[index] = rule
            index = index + 1
    with open(target_dir + "/" + "scirius-iprep.list", 'w') as rfile:
        for cate in cat_map:
            iprep_group = cat_map[cate].sid
            for IP in cat_map[cate].group_ips_list.split(','):
                rfile.write('%s,%d,100\n' % (IP, cate))
