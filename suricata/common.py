"""
Copyright(C) 2015, Stamus Networks
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
import psutil
from rest_framework import serializers

from django.conf import settings


if settings.SURICATA_UNIX_SOCKET:
    try:
        import suricatasc
    except:
        settings.SURICATA_UNIX_SOCKET = None

class Info():
    def status(self):
        suri_running = 'danger'
        if settings.SURICATA_UNIX_SOCKET:
            sc = suricatasc.SuricataSC(settings.SURICATA_UNIX_SOCKET)
            try:
                sc.connect()
            except:
                return 'danger'
            res = sc.send_command('uptime', None)
            if res['return'] == 'OK':
                suri_running = 'success'
            sc.close()
        else:
            for proc in psutil.process_iter():
                try:
                    pinfo = proc.as_dict(attrs=['name'])
                except psutil.NoSuchProcess:
                    pass
                else:
                    if pinfo['name'] == 'Suricata-Main':
                        suri_running = 'success'
                        break
        return suri_running
    def disk(self):
        return psutil.disk_usage('/')
    def memory(self):
        return psutil.virtual_memory()

    def used_memory(self):
        mem = psutil.virtual_memory()
        return round(mem.used * 100. / mem.total, 1)

    def cpu(self):
        return psutil.cpu_percent(interval=0.2)

def get_es_template():
    return 'rules/elasticsearch.html'

def help_links(djlink):
    HELP_LINKS_TABLE = {
        "suricata_edit": {"name": "Suricata setup", "base_url": "doc/suricata-ce.html", "anchor": "#setup" },
        "suricata_update": {"name": "Updating Suricata ruleset", "base_url": "doc/suricata-ce.html", "anchor": "#updating-ruleset" },
        }
    if HELP_LINKS_TABLE.has_key(djlink):
        return HELP_LINKS_TABLE[djlink]
    return None


def get_user_actions_dict():
    from rules.models import UserAction
    return UserAction.get_user_actions_dict()


def get_hunt_filters():
    from rules.models import get_hunt_filters
    return get_hunt_filters()


def validate_rule_postprocessing(data, partial):
    action = data.get('action')
    if not partial and action not in ('suppress', 'threshold'):
        raise serializers.ValidationError('Action "%s" is not supported.' % action)

    has_ip = False
    has_bad_operator = False

    signatures = {
        'alert.signature_id': False,
        'alert.signature': False,
        'msg': False,
        'content': False,
    }

    for f in data.get('filter_defs', []):
        if f.get('key') in signatures.keys():
            signatures[f.get('key')] = True
            if signatures.values().count(True) > 1:
                raise serializers.ValidationError({'filter_defs': ['Only one field with key "alert.signature_id" or "msg" or "alert.signature" or "content" is accepted.']})

        if f.get('key') in ('src_ip', 'dest_ip', 'alert.target.ip', 'alert.source.ip'):
            if action == 'suppress':
                if has_ip:
                    raise serializers.ValidationError({'filter_defs': ['Only one field with key "src_ip" or "dest_ip" or "alert.source.ip" or "alert.target.ip" is accepted.']})
                has_ip = True
            else:
                raise serializers.ValidationError({'filter_defs': ['Field "%s" is not supported for threshold.' % f['key']]})

        if f.get('operator') != 'equal':
            has_bad_operator = True

    if action == 'threshold':
        has_ip = True

    errors = []
    if not partial:
        if signatures.values().count(False) == len(signatures):
            errors.append('A filter with a key "alert.signature_id" or "msg" or "alert.signature" or "content" is required.')

        if signatures.values().count(True) > 1:
            errors.append('Only one filter with a key "alert.signature_id" or "msg" or "alert.signature" or "content" can be set.')

        if not has_ip:
            errors.append('A filter with a key "src_ip" or "dest_ip" or "alert.source.ip" or "alert.target.ip" is required.')
    if has_bad_operator:
        errors.append('Only operator "equal" is supported.')

    if errors:
        raise serializers.ValidationError({'filter_defs': errors})

def get_processing_filter_thresholds(ruleset):
    from rules.models import RuleProcessingFilter

    for f in ruleset.processing_filters.filter(enabled=True, action__in=('suppress', 'threshold')):
        for item in f.get_threshold_content(ruleset):
            yield item


PROCESSING_FILTER_FIELDS = set(('src_ip', 'dest_ip', 'alert.signature_id', 'alert.target.ip', 'alert.source.ip', 'msg', 'alert.signature', 'content'))
PROCESSING_THRESHOLD_FIELDS = set(('alert.signature_id', 'msg', 'alert.signature', 'content'))


def get_processing_actions_capabilities(fields):
    return (('suppress', 'Suppress'), ('threshold', 'Threshold'))


def get_processing_filter_capabilities(fields, action):
    if action == 'suppress':
        return {
            'fields': sorted(list(PROCESSING_FILTER_FIELDS & set(fields))),
            'operators': ['equal']
        }
    elif action == 'threshold':
        return {
            'fields': sorted(list(PROCESSING_THRESHOLD_FIELDS & set(fields))),
            'operators': ['equal']
        }
    return { 'fields': [], 'operators': ['equal'] }


def update_processing_filter_action_options_serializer(dictionary):
    return dictionary


def update_proessing_filter_action_options(rule_processing):
    return rule_processing


def get_homepage_context():
    context = {
        'title': 'Scirius Community Edition',
        'content_lead': 'Scirius CE is a web application for threat hunting and Suricata ruleset management.',
        'content_minor1': 'Scirius CE is developed by Stamus Networks and is available under the GNU GPLv3 license.',
        'content_minor2': 'Manage multiple rulesets and rules sources. Upload and manage custom rules and any data files. Handle thresholding and suppression to limit verbosity of noisy alerts. Get suricata performance statistics and information about rules activity.',
        'content_minor3': 'Interact with Elasticsearch, Kibana and other interfaces such as EveBox.',
        'admin_title': 'Ruleset setup and Suricata management',
        'version': settings.SCIRIUS_FLAVOR + " v" + settings.SCIRIUS_VERSION,
        'icon': False,
        'nb_probes': 1
    }
    return context


def get_default_filter_sets():
    from rules.models import FilterSet

    fsets = FilterSet.get_default_filter_sets()
    for idx, fset in enumerate(fsets):
        fset['id'] = -idx

    return fsets

def es_bool_clauses(request):
    return ''


def es_query_string(request):
    return ''


def check_es_version(request):
    from rules.es_graphs import ESVersion, ESError

    try:
        es_version = ESVersion(request).get()
    except ESError as e:
        return {'error': e.args[0]}

    return {'es_is_good_version': True, 'es_version': es_version}


def update_context(request):
    return {}


def custom_source_datatype():
    return tuple()


def update_source_content_type(content_type, source=None):
    return content_type


def update_custom_source(source_path):
    pass


def extract_custom_source(f, source_path):
    pass
