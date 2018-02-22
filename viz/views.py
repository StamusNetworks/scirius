# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render

def dashboard(request):
    context = {}
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

def pktcity(request):
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
    return scirius_render(request, 'suricata/pktcity.html', context)
