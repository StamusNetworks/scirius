# -*- coding: utf-8 -*-

"""
Copyright(C) 2018, Stamus Networks
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

from scirius.utils import scirius_render
from django.conf import settings

PROBE = __import__(settings.RULESET_MIDDLEWARE)


def dashboard(request):
    context = {}
    context['probes'] = map(lambda x: '"' + x + '"', PROBE.models.get_probe_hostnames())

    if request.method == 'POST' and 'filter' in request.POST:
        context['filter'] = request.POST['filter']
        request.session['filter'] = request.POST['filter']
    else:
        context['filter'] = request.session.get('filter', '*')

    if request.GET.__contains__('reload'):
        reload = int(request.GET.get('reload', '300'))
        request.session['reload'] = reload
    else:
        reload = int(request.session.get('reload', '300'))

    context['reload'] = reload
    return scirius_render(request, 'viz/dashboard.html', context)


def dashboard_target(request):
    context = {}
    context['probes'] = map(lambda x: '"' + x + '"', PROBE.models.get_probe_hostnames())

    if request.method == 'POST' and 'filter' in request.POST:
        context['filter'] = request.POST['filter']
        request.session['filter'] = request.POST['filter']
    else:
        context['filter'] = request.session.get('filter', '*')

    if request.GET.__contains__('reload'):
        reload = int(request.GET.get('reload', '300'))
        request.session['reload'] = reload
    else:
        reload = int(request.session.get('reload', '300'))

    context['reload'] = reload
    return scirius_render(request, 'viz/dashboard_target.html', context)


def pktcity(request):
    context = {}
    if request.method == 'POST' and 'filter' in request.POST:
        context['filter'] = request.POST['filter']
        request.session['filter'] = request.POST['filter']
    else:
        context['filter'] = request.session.get('filter', '*')

    if request.GET.__contains__('reload'):
        reload = int(request.GET.get('reload', '300'))
        request.session['reload'] = reload
    else:
        reload = int(request.session.get('reload', '300'))

    context['reload'] = reload
    return scirius_render(request, 'viz/pktcity.html', context)
