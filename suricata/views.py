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

from time import time
import socket

from django.shortcuts import render, redirect
from django.db import IntegrityError

from django.utils import timezone

# Create your views here.
from django.http import HttpResponse

from scirius.utils import scirius_render

from suricata.models import Suricata
from rules.models import dependencies_check
from rules.models import UserAction

from forms import *
from rules.forms import CommentForm

from rules.views import complete_context
from rules.es_graphs import es_get_ippair_alerts

from django.conf import settings
if settings.USE_ELASTICSEARCH:
    from rules.es_graphs import *

def get_suri():
    suri = Suricata.objects.all()
    if suri:
        suri = suri[0]
    return suri

def index(request, error = None):
    # try to get suricata from db
    suri = get_suri()
    if settings.SURICATA_NAME_IS_HOSTNAME:
        suri.name = socket.gethostname()

    if suri:
        context = {'suricata': suri}
        if error:
            context['error'] = error
        if suri.ruleset:
            supp_rules = list(suri.ruleset.suppressed_rules.all())
            if len(supp_rules):
                suppressed = ",".join([ str(x.sid) for x in supp_rules])
                context['suppressed'] = suppressed

        if settings.USE_ELASTICSEARCH:
            context['rules'] = True
            complete_context(request, context)

        return scirius_render(request, 'suricata/index.html', context)
    else:
        form = SuricataForm()
        context = { 'creation': True , 'form': form}
        missing = dependencies_check(Suricata)
        if missing:
            context['missing'] = missing
        return scirius_render(request, 'suricata/edit.html', context)


def edit(request):
    suri = get_suri()

    if not request.user.is_staff:
        return redirect('/')

    if request.method == 'POST':
        if suri:
            suri.updated_date = timezone.now()
            form = SuricataForm(request.POST, instance = suri)
        else:
            form = SuricataForm(request.POST)
        if form.is_valid():
            if suri:
                form.save()
                ua = UserAction(action='modify', options='suricata', user = request.user, userobject = suri, comment = form.cleaned_data['comment'])
                ua.save()
                return redirect(index)
            try:
                suricata = Suricata.objects.create(name = form.cleaned_data['name'],
                        descr = form.cleaned_data['descr'],
                        output_directory = form.cleaned_data['output_directory'],
                        created_date = timezone.now(),
                        updated_date = timezone.now(),
                        ruleset = form.cleaned_data['ruleset'],
                        yaml_file = form.cleaned_data['yaml_file'],
                        )
            except IntegrityError, error:
                return scirius_render(request, 'suricata/edit.html', { 'form': form, 'error': error })
            ua = UserAction(action='create', options='suricata', user = request.user, userobject = suricata, comment = form.cleaned_data['comment'])
            ua.save()
            return redirect(index)
        else:
            return scirius_render(request, 'suricata/edit.html', { 'form': form, 'error': 'Invalid form' })
    else:
        if suri:
            form = SuricataForm(instance = suri)
        else:
            form = SuricataForm()
    missing = dependencies_check(Suricata)

    return scirius_render(request, 'suricata/edit.html', { 'form': form, 'missing': missing })


def update(request):
    suri = get_suri()

    if not request.user.is_staff:
        return redirect('/')

    if suri == None:
        form = SuricataForm()
        context = { 'creation': True , 'form': form}
        return scirius_render(request, 'suricata/edit.html', context)
    if request.method == 'POST':
        form = SuricataUpdateForm(request.POST)
        if not form.is_valid():
            return scirius_render(request, 'suricata/update.html', { 'suricata': suri, 'error': "Invalid form"})
        message = []
        if form.cleaned_data['reload']:
            try:
                suri.ruleset.update()
            except IOError, errors:
                return index(request, error="Can not fetch data: %s" % (errors))
            message.append("Rule downloaded at %s. " % (suri.ruleset.updated_date) + ".")
        if form.cleaned_data['build']:
            suri.generate()
            suri.updated_date = timezone.now()
            suri.save()
            message.append("Successful ruleset build at " + str(suri.updated_date) + ".")
        if form.cleaned_data['push']:
            ret = suri.push()
            suri.updated_date = timezone.now()
            suri.save()
            if ret:
                message.append("Successful asked ruleset reload at " + str(suri.updated_date))
            else:
                message.append("Suricata restart already asked.")

        ua = UserAction(action='modify', options='ruleset', user = request.user, userobject = suri, comment = form.cleaned_data['comment'])
        ua.save()
        context =  { 'message': message, 'suricata': suri }
        return scirius_render(request, 'suricata/update.html', context)
    else:
        return scirius_render(request, 'suricata/update.html', { 'suricata': suri, 'form': CommentForm() })


def dashboard(request):
    context = {}
    complete_context(request, context)
    suri = get_suri()
    context['probes'] = ("'"+ suri.name + "'",)
    if request.method == 'POST' and request.POST.has_key('filter'):
        context['filter'] = request.POST['filter']
        request.session['filter'] =  request.POST['filter']
    else:
        context['filter'] = request.session.get('filter', '*')
    if request.GET.__contains__('reload'):
        reload = int(request.GET.get('reload', '300'))
        request.session['reload'] = reload
    else:
        reload = int(request.session.get('reload', '300'))
    context['reload'] = reload
    if suri.ruleset:
        supp_rules = list(suri.ruleset.suppressed_rules.all())
        if len(supp_rules):
            suppressed = ",".join([ str(x.sid) for x in supp_rules])
            context['suppressed'] = suppressed
    return scirius_render(request, 'suricata/dashboard.html', context)
