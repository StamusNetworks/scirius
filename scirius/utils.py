"""
Copyright(C) 2014,2015,  Stamus Networks
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


from importlib import import_module
from time import time

from django.shortcuts import render
from django.conf import settings
from django.utils import timezone
from django.contrib import messages

import django_tables2 as tables

from accounts.models import SciriusUser
from rules.models import get_system_settings


def build_path_info(request):
    splval = request.path_info.strip('/ ').split('/')
    if splval[0] == 'rules':
        try:
            splval.remove('pk')
        except ValueError:
            pass
        splval = splval[1:]
    if len(splval):
        return " - ".join(splval)
    else:
        return "home"


class TimezoneMiddleware(object):
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            try:
                user = SciriusUser.objects.get(user=request.user)
            except:
                return self.get_response(request)
            if user:
                timezone.activate(user.timezone)
        return self.get_response(request)


def complete_context(request, context):
    if get_system_settings().use_elasticsearch:
        if request.GET.__contains__('duration'):
            duration = int(request.GET.get('duration', '24'))
            if duration > 24 * 30:
                duration = 24 * 30
            request.session['duration'] = duration
        else:
            duration = int(request.session.get('duration', '24'))

        from_date = int((time() - (duration * 3600)) * 1000)
        if duration <= 24:
            date = '%ih' % int(duration)
        else:
            date = '%id' % int(duration / 24)

        context['draw_func'] = 'draw_sunburst'
        context['draw_elt'] = 'path'

        context['date'] = date
        context['from_date'] = from_date
        context['time_range'] = duration * 3600


def scirius_render(request, template, context):
    context['generator'] = settings.RULESET_MIDDLEWARE
    context['path_info'] = build_path_info(request)
    context['scirius_release'] = settings.SCIRIUS_FLAVOR + " v" + settings.SCIRIUS_VERSION
    context['scirius_long_name'] = settings.SCIRIUS_LONG_NAME
    gsettings = get_system_settings()
    if settings.USE_INFLUXDB:
        context['influxdb'] = 1
    if settings.USE_SURICATA_STATS:
        context['suricata_stats'] = 1
    if settings.USE_LOGSTASH_STATS:
        context['logstash_stats'] = 1
    if settings.HAVE_NETINFO_AGG:
        context['netinfo_agg'] = 1
    if gsettings.use_elasticsearch:
        context['elasticsearch'] = 1
        if settings.USE_KIBANA:
            context['kibana'] = 1
            if settings.KIBANA_PROXY:
                context['kibana_url'] = "/kibana"
            else:
                context['kibana_url'] = settings.KIBANA_URL
    if settings.USE_EVEBOX:
        context['evebox'] = 1
        context['evebox_url'] = "/evebox"
    if settings.SCIRIUS_HAS_DOC:
        djurl = request.resolver_match
        context['help_link'] = help_links(djurl.view_name)
    if settings.SCIRIUS_IN_SELKS:
        context['in_selks'] = 1

    context['toplinks'] = [{
        'id': 'suricata',
        'url': '/suricata/',
        'icon': 'eye-open',
        'label': 'Suricata'
    }]
    context['monitoring_url'] = 'suricata_index'

    context.update(get_middleware_module('common').update_context(request))
    context['messages'] = messages.get_messages(request)
    complete_context(request, context)
    return render(request, template, context)


def scirius_listing(request, objectname, name, template='rules/object_list.html', table=None, adduri=None):
    # FIXME could be improved by generating function name
    from accounts.tables import UserTable
    from rules.tables import CategoryTable
    assocfn = {'Categories': CategoryTable, 'Users': UserTable}
    olist = objectname.objects.all()

    if olist:
        if table is None:
            data = assocfn[name](olist)
        else:
            data = table(olist)
        tables.RequestConfig(request).configure(data)
        data_len = len(olist)
    else:
        data = None
        data_len = 0

    context = {'objects': data, 'name': name, 'objects_len': data_len}
    try:
        objectname.editable
        context['action'] = objectname.__name__.lower()
    except:
        pass

    if adduri:
        context['action'] = True
        context['adduri'] = adduri
    return scirius_render(request, template, context)


def get_middleware_module(module):
    return import_module('%s.%s' % (settings.RULESET_MIDDLEWARE, module))


def help_links(djlink):
    HELP_LINKS_TABLE = {
        "sources": {"name": "Creating a source", "base_url": "doc/ruleset.html", "anchor": "#creating-source"},
        "add_source": {"name": "Add a custom source", "base_url": "doc/ruleset.html", "anchor": "#manual-addition"},
        "add_public_source": {"name": "Add a public source", "base_url": "doc/ruleset.html", "anchor": "#public-sources"},
        "threshold_rule": {"name": "Suppression and thresholding", "base_url": "doc/ruleset.html", "anchor": "#suppression-and-thresholding"},
        "add_ruleset": {"name": "Ruleset creation", "base_url": "doc/ruleset.html", "anchor": "#creating-ruleset"},
        "edit_ruleset": {"name": "Edit Ruleset", "base_url": "doc/ruleset.html", "anchor": "#editing-ruleset"},
        "edit_rule": {"name": "Transform Rule", "base_url": "doc/ruleset.html", "anchor": "#rule-transformations"},
        "accounts_manage": {"name": "Accounts Management", "base_url": "doc/local-user-management.html", "anchor": "#manage-accounts"},
    }
    if djlink in HELP_LINKS_TABLE:
        return HELP_LINKS_TABLE[djlink]
    Probe = __import__(settings.RULESET_MIDDLEWARE)
    return Probe.common.help_links(djlink)


# Based on https://github.com/jieter/django-tables2/blob/master/CHANGELOG.md#breaking-changes-200
class SciriusTable(tables.Table):
    def get_column_class_names(self, classes_set, bound_column):
        classes_set = super(SciriusTable, self).get_column_class_names(classes_set, bound_column)
        classes_set.add(bound_column.name)
        return classes_set


# https://stackoverflow.com/questions/20656135/python-deep-merge-dictionary-data
def merge_dict_deeply(src, dest):
    for key, value in list(src.items()):
        if isinstance(value, dict):
            node = dest.setdefault(key, {})
            merge_dict_deeply(value, node)
        else:
            dest[key] = value
    return dest
