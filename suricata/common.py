"""
Copyright(C) 2015-2020, Stamus Networks
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


import psutil
from rest_framework import serializers

from django.conf import settings


if settings.SURICATA_UNIX_SOCKET:
    try:
        import suricata.sc as suricatasc
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
                return {'probe': 'danger'}
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
        return {'probe': suri_running}

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


def has_extra_auth():
    return False


def has_multitenant():
    return False


def get_tenants(empty_queryset=False):
    return []


def update_scirius_user_class(user, data):
    pass


def help_links(djlink):
    HELP_LINKS_TABLE = {
        "suricata_edit": {"name": "Suricata setup", "base_url": "doc/suricata-ce.html", "anchor": "#setup"},
        "suricata_update": {"name": "Updating Suricata ruleset", "base_url": "doc/suricata-ce.html", "anchor": "#updating-ruleset"},
    }
    if djlink in HELP_LINKS_TABLE:
        return HELP_LINKS_TABLE[djlink]
    return None


def get_user_actions_dict():
    from rules.models import UserAction
    return UserAction.get_user_actions_dict()


def get_hunt_filters():
    from rules.models import get_hunt_filters
    return get_hunt_filters()


def validate_rule_postprocessing(data, partial, serializer):
    action = data.get('action')
    if not partial and action not in ('suppress',):
        raise serializers.ValidationError('Action "%s" is not supported.' % action)
    serializer.validate_rule_postprocessing(data, partial)


PROCESSING_FILTER_FIELDS = set(('src_ip', 'dest_ip', 'alert.signature_id', 'alert.target.ip', 'alert.source.ip', 'msg', 'alert.signature', 'content'))
PROCESSING_THRESHOLD_FIELDS = set(('alert.signature_id', 'msg', 'alert.signature', 'content'))


def get_processing_actions_capabilities(fields):
    return (('suppress', 'Suppress'), ('threshold', 'Threshold'))


def get_processing_filter_capabilities(fields, action):
    if action == 'suppress':
        return {
            'fields': sorted(list(PROCESSING_FILTER_FIELDS & set(fields))),
            'operators': ['equal'],
            'supported_fields': ', '.join(PROCESSING_FILTER_FIELDS)
        }
    elif action == 'threshold':
        return {
            'fields': sorted(list(PROCESSING_THRESHOLD_FIELDS & set(fields))),
            'operators': ['equal'],
            'supported_fields': ', '.join(PROCESSING_THRESHOLD_FIELDS)
        }
    return {'fields': [], 'operators': ['equal'], 'supported_fields': ''}


def update_processing_filter_action_options_serializer(dictionary):
    return dictionary


def update_processing_filter_action_options(rule_processing):
    return rule_processing


def get_homepage_context():
    context = {
        'title': 'Scirius Community Edition',
        'short_title': 'Scirius CE',
        'common_name': 'Scirius',
        'common_long_name': 'Scirius Community Edition',
        'content_lead': 'Scirius CE is a web application for threat hunting and Suricata ruleset management of one sensor.',
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
    return {}


def es_query_string(request):
    return ''


def check_es_version(request, es_url):
    from rules.es_graphs import ESVersion, ESError

    try:
        es_version = ESVersion(None, es_url).get()
    except ESError as e:
        return {'error': e.args[0]}

    return {'es_is_good_version': True, 'es_version': es_version}


def update_context(request):
    return {}


def custom_source_datatype(check_conf=False):
    return tuple()


def update_source_content_type(content_type, source=None):
    return content_type


def update_custom_source(source_path):
    pass


def extract_custom_source(f, source_path):
    pass


def get_sources():
    from rules.models import Source
    return Source.objects.all()


def update_settings(data):
    pass


def extra_ruleset_form(request):
    return None


def data_export():
    pass


def update_policies(proc_filter):
    pass


def delete_policies():
    pass


def extract_policies(item):
    return {}


def import_policies(filter_, method_dict=None, threat_dict=None):
    pass


def changelog_ruleset(request, ruleset):
    from rules.views import build_source_diff
    from scirius.utils import scirius_render

    url = 'rules/ruleset.html'
    diff = ruleset.diff()

    for key in diff:
        cdiff = diff[key]
        build_source_diff(request, cdiff)
        diff[key] = cdiff

    context = {'ruleset': ruleset, 'diff': diff, 'mode': 'changelog'}
    return scirius_render(request, url, context)


def es_version_changed():
    pass


def sn_loggers():
    return {}


def use_stamuslogger():
    return False
