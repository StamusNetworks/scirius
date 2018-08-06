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

import psutil
import subprocess
import tempfile
import shutil
import os
import json
import StringIO
import re

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

    has_sid = False
    has_ip = False
    has_bad_operator = False

    for f in data.get('filter_defs', []):
        if f.get('key') == 'alert.signature_id':
            has_sid = True

        if f.get('key') in ('src_ip', 'dest_ip'):
            if action == 'suppress':
                if has_ip:
                    raise serializers.ValidationError({'filter_defs': ['Only one field with key "src_ip" or "dest_ip" is accepted.']})
                has_ip = True
            else:
                raise serializers.ValidationError({'filter_defs': ['Field "%s" is not supported for threshold.' % f['key']]})

        if f.get('operator') != 'equal':
            has_bad_operator = True

    if action == 'threshold':
        has_ip = True

    errors = []
    if not partial:
        if not has_sid:
            errors.append('A filter with a key "alert.signature_id" is required.')
        if not has_ip:
            errors.append('A filter with a key "src_ip" or "dest_ip" is required.')
    if has_bad_operator:
        errors.append('Only operator "equal" is supported.')

    if errors:
        raise serializers.ValidationError({'filter_defs': errors})

def get_processing_filter_thresholds(ruleset):
    from rules.models import RuleProcessingFilter

    for f in ruleset.processing_filters.filter(enabled=True, action__in=('suppress', 'threshold')):
        yield f.get_threshold_content()


PROCESSING_FILTER_FIELDS = set(('src_ip', 'dest_ip', 'alert.signature_id'))
PROCESSING_THRESHOLD_FIELDS = set(('alert.signature_id',))


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
