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
from dateutil.relativedelta import relativedelta

from django.shortcuts import redirect
from django.contrib.auth.decorators import permission_required
from django.utils import timezone

from scirius.utils import scirius_render

# import task to be seen by MIDDLEWARE
from suricata.tables import RecurrentTaskTable  # noqa: F401
from suricata.forms import SuricataForm, SuricataUpdateForm
from suricata.models import Suricata
from rules.models import SuppressedRuleAtVersion, dependencies_check
from rules.models import UserAction, Rule

from django.conf import settings
if settings.USE_ELASTICSEARCH:
    from rules.es_graphs import *  # noqa: F403, F401


def get_suri():
    return Suricata.objects.first()


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
        form = SuricataForm(request.POST, instance=suri)
        if form.is_valid():
            creation = suri is None
            suri = form.save()
            UserAction.create(
                action_type='edit_suricata' if not creation else 'create_suricata',
                comment=form.cleaned_data['comment'],
                request=request,
                suricata=suri
            )
            return redirect(index)

        else:
            return scirius_render(
                request,
                'suricata/edit.html',
                {'form': form, 'error': 'Invalid form'}
            )
    else:
        form = SuricataForm(instance=suri)
    missing = dependencies_check(Suricata)

    return scirius_render(request, 'suricata/edit.html', {'form': form, 'missing': missing})


@permission_required('rules.ruleset_update_push', raise_exception=True)
def update(request):
    suri = get_suri()

    if suri is None:
        form = SuricataForm()
        context = {'creation': True, 'form': form}
        return scirius_render(request, 'suricata/edit.html', context)

    date_time = timezone.now() + relativedelta(days=1, hour=2, minute=0, second=0, microsecond=0)
    context = {
        'suricata': suri,
        'recurrence': False,
        'schedule': False,
        'recurrence_param': 'daily',
        'schedule_param': date_time.strftime('%Y/%m/%d %H:%M'),
    }
    if request.method == 'POST':
        form = SuricataUpdateForm(request.POST)
        if not form.is_valid():
            context.update({'form': form})
            return scirius_render(
                request,
                'suricata/update.html',
                context
            )

        task = form.spawn(user=request.user, ruleset_pk=suri.ruleset.pk)

        UserAction.create(
            action_type='edit_suricata',
            comment=form.cleaned_data['comment'],
            request=request,
            suricata=suri
        )
        return redirect('status' if not task.is_recurrent else 'view_stasks')
    else:
        form = SuricataUpdateForm()
        context.update({'form': form})
        return scirius_render(
            request,
            'suricata/update.html',
            context
        )
