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

import socket

from django.shortcuts import redirect
from django.db import IntegrityError
from django.contrib.auth.decorators import permission_required

from django.utils import timezone
from scirius.utils import scirius_render

from suricata.forms import SuricataForm, SuricataUpdateForm
from suricata.models import Suricata
from rules.models import SuppressedRuleAtVersion, dependencies_check
from rules.models import UserAction, Rule

from rules.forms import CommentForm

from django.conf import settings
if settings.USE_ELASTICSEARCH:
    from rules.es_graphs import *  # noqa: F403, F401


def get_suri():
    suri = Suricata.objects.all()
    if suri:
        suri = suri[0]
    return suri


def index(request, error=None):
    # try to get suricata from db
    suri = get_suri()
    if settings.SURICATA_NAME_IS_HOSTNAME:
        suri.name = socket.gethostname()

    if suri:
        context = {'suricata': suri}
        if error:
            context['error'] = error
        if suri.ruleset:
            suppr_rules = Rule.objects.filter(
                pk__in=SuppressedRuleAtVersion.objects.filter(
                    ruleset=suri.ruleset
                ).values_list('rule_at_version__rule__pk', flat=True).distinct()
            )

            if suppr_rules.count():
                suppressed = ",".join([str(x.sid) for x in suppr_rules.all()])
                context['suppressed'] = suppressed

        if settings.USE_ELASTICSEARCH:
            context['rules'] = True

        return scirius_render(request, 'suricata/index.html', context)
    else:
        form = SuricataForm()
        context = {'creation': True, 'form': form}
        missing = dependencies_check(Suricata)
        if missing:
            context['missing'] = missing
        return scirius_render(request, 'suricata/edit.html', context)


@permission_required('rules.configuration_edit', raise_exception=True)
def edit(request):
    suri = get_suri()

    if request.method == 'POST':
        if suri:
            suri.updated_date = timezone.now()
            form = SuricataForm(request.POST, instance=suri)
        else:
            form = SuricataForm(request.POST)
        if form.is_valid():
            if suri:
                form.save()
                UserAction.create(
                    action_type='edit_suricata',
                    comment=form.cleaned_data['comment'],
                    request=request,
                    suricata=suri
                )
                return redirect(index)
            try:
                suricata = Suricata.objects.create(
                    name=form.cleaned_data['name'],
                    descr=form.cleaned_data['descr'],
                    output_directory=form.cleaned_data['output_directory'],
                    created_date=timezone.now(),
                    updated_date=timezone.now(),
                    ruleset=form.cleaned_data['ruleset'],
                    yaml_file=form.cleaned_data['yaml_file'],
                )
            except IntegrityError as error:
                return scirius_render(
                    request,
                    'suricata/edit.html',
                    {'form': form, 'error': error}
                )

            UserAction.create(
                action_type='create_suricata',
                comment=form.cleaned_data['comment'],
                request=request,
                suricata=suricata
            )
            return redirect(index)
        else:
            return scirius_render(
                request,
                'suricata/edit.html',
                {'form': form, 'error': 'Invalid form'}
            )
    else:
        if suri:
            form = SuricataForm(instance=suri)
        else:
            form = SuricataForm()
    missing = dependencies_check(Suricata)

    return scirius_render(request, 'suricata/edit.html', {'form': form, 'missing': missing})


@permission_required('rules.ruleset_update_push', raise_exception=True)
def update(request):
    suri = get_suri()

    if suri is None:
        form = SuricataForm()
        context = {'creation': True, 'form': form}
        return scirius_render(request, 'suricata/edit.html', context)

    if request.method == 'POST':
        form = SuricataUpdateForm(request.POST)
        if not form.is_valid():
            return scirius_render(
                request,
                'suricata/update.html',
                {'suricata': suri, 'error': "Invalid form"}
            )

        message = []
        if form.cleaned_data['reload']:
            try:
                suri.ruleset.update()
            except IOError as errors:
                return index(request, error="Can not fetch data: %s" % (errors))

            message.append("Rule downloaded at %s." % str(suri.ruleset.updated_date))
        if form.cleaned_data['build']:
            suri.generate()
            suri.updated_date = timezone.now()
            suri.save()
            message.append("Successful ruleset build at %s." % str(suri.updated_date))

        if form.cleaned_data['push']:
            ret = suri.push()
            suri.updated_date = timezone.now()
            suri.save()

            if ret:
                message.append("Successful asked ruleset reload at %s." % str(suri.updated_date))
            else:
                message.append("Suricata restart already asked.")

        UserAction.create(
            action_type='edit_suricata',
            comment=form.cleaned_data['comment'],
            request=request,
            suricata=suri
        )
        context = {'message': message, 'suricata': suri}
        return scirius_render(request, 'suricata/update.html', context)
    else:
        return scirius_render(
            request,
            'suricata/update.html',
            {'suricata': suri, 'form': CommentForm()}
        )
