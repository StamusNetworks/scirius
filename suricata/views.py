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

from datetime import datetime

from django.shortcuts import render, redirect
from django.db import IntegrityError

# Create your views here.
from django.http import HttpResponse

from scirius.utils import scirius_render

from suricata.models import Suricata

from forms import *

def index(request):
    # try to get suricata from db
    suri = Suricata.objects.all()
    if suri:
        suri = suri[0]
        context = {'suricata': suri}
        return scirius_render(request, 'suricata/index.html', context)
    else:
        form = SuricataForm()
        context = { 'creation': True , 'form': form}
        return scirius_render(request, 'suricata/edit.html', context)


def edit(request):
    suri = Suricata.objects.all()
    if suri:
        suri = suri[0]

    if request.method == 'POST':
        if suri:
            suri.updated_date = datetime.now()
            form = SuricataForm(request.POST, instance = suri)
        else:
            form = SuricataForm(request.POST)
        if form.is_valid():
            if suri:
                form.save()
                return redirect(index)
            try:
                suricata = Suricata.objects.create(name = form.cleaned_data['name'],
                        descr = form.cleaned_data['descr'],
                        output_directory = form.cleaned_data['output_directory'],
                        created_date = datetime.now(),
                        updated_date = datetime.now(),
                        ruleset = form.cleaned_data['ruleset'],
                        )
                suricata.save()
            except IntegrityError, error:
                return scirius_render(request, 'suricata/edit.html', { 'form': form, 'error': error })
            return redirect(index)
        else:
            return scirius_render(request, 'suricata/edit.html', { 'form': form, 'error': 'Invalid form' })
    else:
        if suri:
            form = SuricataForm(instance = suri)
        else:
            form = SuricataForm()
    return scirius_render(request, 'suricata/edit.html', { 'form': form })
