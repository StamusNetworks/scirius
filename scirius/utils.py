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

from django.shortcuts import render
from django.conf import settings
import django_tables2 as tables

from rules.tables import *
from accounts.tables import UserTable

def scirius_render(request, template, context):
    context['generator'] = settings.RULESET_MIDDLEWARE
    if settings.USE_ELASTICSEARCH:
        context['elasticsearch'] = 1
    if settings.USE_KIBANA:
        context['kibana'] = 1
        if settings.KIBANA_PROXY:
            context['kibana_url'] = "/kibana"
        else:
            context['kibana_url'] = settings.KIBANA_URL
    return render(request, template, context)

def scirius_listing(request, objectname, name, template = 'rules/object_list.html', table = None, adduri = None):
    # FIXME could be improved by generating function name
    assocfn = { 'Sources': SourceTable, 'Categories': CategoryTable, 'Rulesets': RulesetTable, 'Users': UserTable }
    olist = objectname.objects.all()
    if olist:
        if table == None:
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
