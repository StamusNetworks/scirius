"""
Copyright(C) 2014-2016, Stamus Networks
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

from django.shortcuts import render, get_object_or_404, redirect
from django.utils import timezone
from django.http import HttpResponse
from django.db import IntegrityError
from django.conf import settings
from elasticsearch.exceptions import ConnectionError
from django.core.exceptions import SuspiciousOperation, ValidationError
from django.contrib import messages

from scirius.utils import scirius_render, scirius_listing

from rules.es_data import ESData
from rules.models import Ruleset, Source, SourceUpdate, Category, Rule, dependencies_check, get_system_settings, Threshold, Transformation, CategoryTransformation, RulesetTransformation, UserAction, UserActionObject
from rules.tables import UpdateRuleTable, DeletedRuleTable, ThresholdTable, HistoryTable

from rules.es_graphs import *

import json
import yaml
import re
import os

from time import time
import django_tables2 as tables
from tables import *
from forms import *
from suripyg import SuriHTMLFormat

Probe = __import__(settings.RULESET_MIDDLEWARE)

# Create your views here.
def index(request):
    ruleset_list = Ruleset.objects.all().order_by('-created_date')[:5]
    source_list = Source.objects.all().order_by('-created_date')[:5]
    context = {'ruleset_list': ruleset_list,
                'source_list': source_list}
    try:
        context['probes'] = map(lambda x: '"' +  x + '"', Probe.models.get_probe_hostnames())
    except:
        pass
    return scirius_render(request, 'rules/index.html', context)

def about(request):
    context = {}
    try:
        from suricata.models import Suricata
        suricata = Suricata.objects.all()
        if suricata != None:
            context['suricata'] = suricata[0]
    except:
        pass
    return scirius_render(request, 'rules/about.html', context)

def search(request):
    context = {}
    length = 0
    rules_width = 4
    search = None
    if request.method == 'POST':
        if request.POST.has_key('search'):
            search = request.POST['search']
            request.GET = request.GET.copy()
            request.GET.update({'search': search})
    elif request.method == 'GET':
        if request.GET.has_key('search'):
            search = request.GET['search']
    if search:
        rules = Rule.objects.filter(content__icontains=search)
        if len(rules) > 0:
            length += len(rules)
            rules = RuleTable(rules)
            tables.RequestConfig(request).configure(rules)
        else:
            rules = None
        categories = Category.objects.filter(name__icontains=search)
        if len(categories) > 0:
            length += len(categories)
            categories = CategoryTable(categories)
            tables.RequestConfig(request).configure(categories)
        else:
            rules_width += 4
            categories = None
        rulesets = Ruleset.objects.filter(name__icontains=search)
        if len(rulesets) > 0:
            length += len(rulesets)
            rulesets = RulesetTable(rulesets)
            tables.RequestConfig(request).configure(rulesets)
        else:
            rules_width += 4
            rulesets = None
    else:
        rules = None
        categories = None
        rulesets = None
    context = { 'rules': rules, 'rules_width': rules_width, 'categories': categories, 'rulesets': rulesets, 'motif': search, 'length': length }
    return scirius_render(request, 'rules/search.html', context)

def sources(request):
    sources = Source.objects.all().order_by('name')
    for source in sources:
        if source.cats_count == 0:
            source.build_counters()
    context = { 'sources': sources }
    return scirius_render(request, 'rules/sources.html', context)

def source(request, source_id, error=None, update = False, activate = False, rulesets = None):
    source = get_object_or_404(Source, pk=source_id)
    cats = CategoryTable(Category.objects.filter(source = source).order_by('name'))
    tables.RequestConfig(request).configure(cats)
    context = {'source': source, 'categories': cats,
               'update': update, 'activate': activate, 'rulesets': rulesets}
    if error:
        context['error'] = error
    if hasattr(Probe.common, 'update_source'):
        context['middleware_has_update'] = True
    return scirius_render(request, 'rules/source.html', context)

def categories(request):
    return scirius_listing(request, Category, 'Categories')

def category(request, cat_id):
    cat = get_object_or_404(Category, pk=cat_id)
    rules = RuleTable(Rule.objects.filter(category = cat, state = True).order_by('sid'))
    tables.RequestConfig(request).configure(rules)
    commented_rules = RuleTable(Rule.objects.filter(category = cat, state = False))
    tables.RequestConfig(request).configure(commented_rules)
    category_path = [ cat.source ]
    # build table of rulesets and display if category is active
    rulesets = Ruleset.objects.all()
    rulesets_status = []

    for ruleset in rulesets:
        status = 'Inactive'
        if cat in ruleset.categories.all():
            status = 'Active'

        transformations = {}
        for key in (Transformation.ACTION, Transformation.LATERAL, Transformation.TARGET):
            trans = cat.get_transformation(ruleset, key, override=True)
            if trans:
                transformations[key] = "%s: %s" % (key.value.capitalize(), trans.value.capitalize())

        rulesets_status.append({
                    'name': ruleset.name,
                    'pk': ruleset.pk,
                    'status': status,
                    'action': transformations[Transformation.ACTION] if Transformation.ACTION in transformations else '',
                    'lateral': transformations[Transformation.LATERAL] if Transformation.LATERAL in transformations else '',
                    'target': transformations[Transformation.TARGET] if Transformation.TARGET in transformations else '',
                })

    rulesets_status = CategoryRulesetTable(rulesets_status)
    tables.RequestConfig(request).configure(rulesets_status)
    context = {'category': cat, 'rules': rules, 'commented_rules': commented_rules, 'object_path': category_path, 'rulesets': rulesets_status}
    return scirius_render(request, 'rules/category.html', context)

class Reference:
    def __init__(self, key, value):
        self.value = value
        self.key = key
        self.url = None

def elasticsearch(request):
    data = None
    RULE_FIELDS_MAPPING = {'rule_src': 'src_ip', 'rule_dest': 'dest_ip', 'rule_source': 'alert.source.ip', 'rule_target': 'alert.target.ip', 'rule_probe': settings.ELASTICSEARCH_HOSTNAME}
    if request.GET.__contains__('query'):
        query = request.GET.get('query', 'dashboards')
        if query == 'dashboards':
            data = es_get_dashboard(count=settings.KIBANA_DASHBOARDS_COUNT)
        elif query == 'rules':
            host = request.GET.get('host', None)
            from_date = request.GET.get('from_date', None)
            qfilter = request.GET.get('filter', None)
            if host != None and from_date != None:
                rules = es_get_rules_stats(request, host, from_date = from_date, qfilter = qfilter)
                if rules == None:
                    return HttpResponse(json.dumps(rules), content_type="application/json")
                context = {'table': rules}
                return scirius_render(request, 'rules/table.html', context)
        elif query == 'rule':
            sid = request.GET.get('sid', None)
            from_date = request.GET.get('from_date', None)
            if from_date != None and sid != None:
                hosts = es_get_sid_by_hosts(request, sid, from_date = from_date)
                context = {'table': hosts}
                return scirius_render(request, 'rules/table.html', context)
        elif query == 'top_rules':
            host = request.GET.get('host', None)
            from_date = request.GET.get('from_date', None)
            qfilter = request.GET.get('filter', None)
            count = request.GET.get('count', 20)
            order = request.GET.get('order', "desc")
            if host != None and from_date != None:
                rules = es_get_top_rules(request, host, from_date = from_date, qfilter = qfilter, count = count, order = order)
                return HttpResponse(json.dumps(rules), content_type="application/json")
        elif query == 'sigs_list':
            host = request.GET.get('host', None)
            from_date = request.GET.get('from_date', None)
            qfilter = request.GET.get('filter', None)
            sids = request.GET.get('sids', None)
            if host != None and from_date != None and sids != None:
                # FIXME sanitize that
                sids = sids.split(',')
                stats = es_get_sigs_list_hits(request, sids, host, from_date = from_date, qfilter = qfilter)
                return HttpResponse(json.dumps(stats), content_type="application/json")
        elif query in RULE_FIELDS_MAPPING.keys():
            filter_ip = RULE_FIELDS_MAPPING[query]
            sid = int(request.GET.get('sid', None))
            from_date = request.GET.get('from_date', None)
            ajax = request.GET.get('json', None)
            if from_date != None and sid != None:
                if ajax:
                    data = es_get_field_stats(request, filter_ip + '.' + settings.ELASTICSEARCH_KEYWORD, '*', from_date = from_date,
                        count = 10,
                        qfilter = 'alert.signature_id:%d' % sid)
                    return HttpResponse(json.dumps(data), content_type="application/json")
                else:
                    hosts = es_get_field_stats_as_table(request, filter_ip + '.' + settings.ELASTICSEARCH_KEYWORD, RuleHostTable, '*', from_date = from_date,
                        count = 10,
                        qfilter = 'alert.signature_id:%d' % sid)
                    context = {'table': hosts}
                    return scirius_render(request, 'rules/table.html', context)
        elif query == 'timeline':
            from_date = request.GET.get('from_date', None)
            cshosts = request.GET.get('hosts', None)
            hosts = cshosts.split(',')
            qfilter = request.GET.get('filter', None)
            data = es_get_timeline(from_date = from_date, hosts = hosts, qfilter = qfilter)
        elif query == 'logstash_eve':
            from_date = request.GET.get('from_date', None)
            value = request.GET.get('value', None)
            cshosts = request.GET.get('hosts', None)
            qfilter = request.GET.get('filter', None)
            if cshosts:
                hosts = cshosts.split(',')
            else:
                hosts = None
            data = es_get_metrics_timeline(from_date = from_date, value = value, hosts = hosts, qfilter = qfilter)
        elif query == 'health':
            data = es_get_health()
        elif query == 'stats':
            data = es_get_stats()
        elif query == 'indices':
            if request.is_ajax():
                indices = ESIndexessTable(es_get_indices())
                tables.RequestConfig(request).configure(indices)
                context = { 'table': indices }
                return scirius_render(request, 'rules/table.html', context)
            else:
                context = {}
                return scirius_render(request, 'rules/elasticsearch.html', context)
        elif query == 'rules_per_category':
            from_date = request.GET.get('from_date', None)
            cshosts = request.GET.get('hosts', None)
            if cshosts:
                hosts = cshosts.split(',')
            else:
                hosts = None
            qfilter = request.GET.get('filter', None)
            data = es_get_rules_per_category(from_date = from_date, hosts = hosts, qfilter = qfilter)
        elif query == 'alerts_count':
            from_date = request.GET.get('from_date', None)
            cshosts = request.GET.get('hosts', None)
            if cshosts:
                hosts = cshosts.split(',')
            else:
                hosts = None
            qfilter = request.GET.get('filter', None)
            prev = request.GET.get('prev', 0)
            data = es_get_alerts_count(from_date = from_date, hosts = hosts, qfilter = qfilter, prev=prev)
        elif query == 'latest_stats':
            from_date = request.GET.get('from_date', None)
            cshosts = request.GET.get('hosts', None)
            if cshosts:
                hosts = cshosts.split(',')
            else:
                hosts = None
            qfilter = request.GET.get('filter', None)
            data = es_get_latest_stats(from_date = from_date, hosts = hosts, qfilter = qfilter)
        elif query == 'ippair_alerts':
            from_date = request.GET.get('from_date', None)
            cshosts = request.GET.get('hosts', None)
            if cshosts:
                hosts = cshosts.split(',')
            else:
                hosts = None
            qfilter = request.GET.get('filter', None)
            data = es_get_ippair_alerts(from_date = from_date, hosts = hosts, qfilter = qfilter)
        elif query == 'ippair_network_alerts':
            from_date = request.GET.get('from_date', None)
            cshosts = request.GET.get('hosts', None)
            if cshosts:
                hosts = cshosts.split(',')
            else:
                hosts = None
            qfilter = request.GET.get('filter', None)
            data = es_get_ippair_network_alerts(from_date = from_date, hosts = hosts, qfilter = qfilter)
        elif query == 'alerts_tail':
            from_date = request.GET.get('from_date', None)
            qfilter = request.GET.get('filter', None)
            data = es_get_alerts_tail(from_date = from_date, qfilter = qfilter)
        elif query == 'suri_log_tail':
            from_date = request.GET.get('from_date', None)
            qfilter = request.GET.get('filter', None)
            cshosts = request.GET.get('hosts', None)
            if cshosts:
                hosts = cshosts.split(',')
            else:
                hosts = None
            data = es_suri_log_tail(from_date=from_date, hosts=hosts)
        else:
            data = None
        return HttpResponse(json.dumps(data), content_type="application/json")
    else:
        if request.is_ajax():
            data = es_get_dashboard(count=settings.KIBANA_DASHBOARDS_COUNT)
            return HttpResponse(json.dumps(data), content_type="application/json")
        else:
            context = {}
            template = Probe.common.get_es_template()
            return scirius_render(request, template, context)

def rule(request, rule_id, key = 'pk'):
    if request.is_ajax():
        rule = get_object_or_404(Rule, sid=rule_id)
        rule.highlight_content = SuriHTMLFormat(rule.content)
        data = { 'msg': rule.msg, 'sid': rule.sid, 'content': rule.content,
                 'highlight_content': rule.highlight_content}
        return HttpResponse(json.dumps(data),
                            content_type="application/json")
    if key == 'pk':
        rule = get_object_or_404(Rule, pk=rule_id)
    else:
        rule = get_object_or_404(Rule, sid=rule_id)
    rule_path = [rule.category.source, rule.category]

    rule.highlight_content = SuriHTMLFormat(rule.content)
    references = []
    for ref in re.findall("reference: *(\w+), *(\S+);", rule.content):
        refer = Reference(ref[0], ref[1])
        if refer.key == 'url':
            if not refer.value.startswith("http"):
                refer.url = "http://" + refer.value
            else:
                refer.url = refer.value
        elif refer.key == 'cve':
            refer.url = "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-" + refer.value
            refer.key = refer.key.upper()
        elif refer.key == 'bugtraq':
            refer.url = "http://www.securityfocus.com/bid/" + refer.value
        references.append(refer)
    
    # build table of rulesets and display if rule is active
    rulesets = Ruleset.objects.all()
    rulesets_status = []
    rule_transformations = False
    
    SUPPRESSED = Transformation.SUPPRESSED
    S_SUPPRESSED = Transformation.S_SUPPRESSED

    for ruleset in rulesets:
        status = 'Inactive'

        if rule.state and rule.category in ruleset.categories.all() and rule not in ruleset.get_transformed_rules(key=SUPPRESSED, value=S_SUPPRESSED):
            status = 'Active'

        threshold = False
        if Threshold.objects.filter(rule=rule, ruleset=ruleset):
            threshold = True

        content = rule.generate_content(ruleset)
        if content:
            content = SuriHTMLFormat(rule.generate_content(ruleset))
        ruleset_info = {'name': ruleset.name, 'pk': ruleset.pk, 'status': status, 'threshold': threshold,
                        'a_drop': False, 'a_filestore': False, 'a_bypass': False,
                        'l_auto': False, 'l_yes': False,
                        't_auto': False, 't_src': False, 't_dst': False,
                        'content': content}

        for TYPE in (Transformation.ACTION, Transformation.LATERAL, Transformation.TARGET):
            trans = rule.get_transformation(ruleset, TYPE, override=True)
            prefix = 'a_'

            if TYPE == Transformation.LATERAL:
                prefix = 'l_'
            if TYPE == Transformation.TARGET:
                prefix = 't_'

            if trans is not None:
                ruleset_info[prefix+trans.value] = True
                if content:
                    rule_transformations = True
        rulesets_status.append(ruleset_info)

    comment_form = RuleCommentForm()
    context = {'rule': rule, 'references': references, 'object_path': rule_path, 'rulesets': rulesets_status,
               'rule_transformations': rule_transformations, 'comment_form': comment_form}

    thresholds = Threshold.objects.filter(rule = rule, threshold_type = 'threshold')
    if thresholds:
        thresholds = RuleThresholdTable(thresholds)
        tables.RequestConfig(request).configure(thresholds)
        context['thresholds'] = thresholds
    suppress = Threshold.objects.filter(rule = rule, threshold_type = 'suppress')
    if suppress:
        suppress = RuleSuppressTable(suppress)
        tables.RequestConfig(request).configure(suppress)
        context['suppress'] = suppress
    try:
        context['probes'] = map(lambda x: '"' +  x + '"', Probe.models.get_probe_hostnames())
    except:
        pass

    return scirius_render(request, 'rules/rule.html', context)

def edit_rule(request, rule_id):
    rule_object = get_object_or_404(Rule, sid=rule_id)

    if not request.user.is_staff:
        context = { 'rule': rule_object, 'error': 'Unsufficient permissions' }
        return scirius_render(request, 'rules/rule.html', context)
        
    if request.method == 'POST': # If the form has been submitted...
        form = RuleTransformForm(request.POST, instance=rule_object)
        if form.is_valid():  # All validation rules pass
            rulesets = form.cleaned_data['rulesets']

            for ruleset in rulesets:
                form_action_trans = Transformation.ActionTransfoType(form.cleaned_data["action"])
                form_lateral_trans = Transformation.LateralTransfoType(form.cleaned_data["lateral"])
                form_target_trans = Transformation.TargetTransfoType(form.cleaned_data["target"])

                for form_trans in (form_action_trans, form_lateral_trans, form_target_trans):
                    (TYPE, NONE, CAT_DEFAULT) = (None, None, None)

                    if form_trans == form_action_trans:
                        TYPE = Transformation.ACTION
                        NONE = Transformation.A_NONE
                        CAT_DEFAULT = Transformation.A_CAT_DEFAULT

                    elif form_trans == form_lateral_trans:
                        TYPE = Transformation.LATERAL
                        NONE = Transformation.L_NO
                        CAT_DEFAULT = Transformation.L_CAT_DEFAULT

                    elif form_trans == form_target_trans:
                        TYPE = Transformation.TARGET
                        NONE = Transformation.T_NONE
                        CAT_DEFAULT = Transformation.T_CAT_DEFAULT

                    else:
                        raise Exception("Key '%s' is unknown")

                    trans = rule_object.get_transformation(ruleset, TYPE)

                    if form_trans == CAT_DEFAULT:
                        cat_trans = rule_object.category.get_transformation(ruleset, TYPE)
                        if cat_trans is None:
                            cat_trans = NONE

                        if trans != cat_trans:
                            UserAction.create(
                                    action_type='transform_rule',
                                    comment=form.cleaned_data['comment'],
                                    user=request.user,
                                    transformation='%s: %s' % (TYPE.value, CAT_DEFAULT.name.replace('_', ' ').title()),
                                    rule=rule_object,
                                    ruleset=ruleset
                            )

                        rule_object.remove_transformations(ruleset, TYPE)
                        continue

                    rule_object.set_transformation(ruleset, key=TYPE, value=form_trans)

                    if form_trans != NONE and form_trans != trans:
                        UserAction.create(
                                action_type='transform_rule',
                                comment=form.cleaned_data['comment'],
                                user=request.user,
                                transformation='%s: %s' % (TYPE.value.title(), form_trans.value.title()),
                                rule=rule_object,
                                ruleset=ruleset
                        )
                    elif form_trans == NONE and trans:
                        UserAction.create(
                                action_type='transform_rule',
                                comment=form.cleaned_data['comment'],
                                user=request.user,
                                transformation='%s: %s' % (TYPE.value.title(), trans.value.title()),
                                rule=rule_object,
                                ruleset=ruleset
                        )

            return redirect(rule_object)
    else:
        rulesets_ids = []
        current_trans = {
                Transformation.ACTION: Transformation.A_CAT_DEFAULT,
                Transformation.LATERAL: Transformation.L_CAT_DEFAULT,
                Transformation.TARGET: Transformation.T_CAT_DEFAULT
        }

        rulesets_res = {
                Transformation.ACTION: {},
                Transformation.LATERAL: {},
                Transformation.TARGET: {},
        }

        initial = {'action': current_trans[Transformation.ACTION].value,
                   'lateral': current_trans[Transformation.LATERAL].value,
                   'target': current_trans[Transformation.TARGET].value,
                   'rulesets': rulesets_ids
                   }

        rulesets = Ruleset.objects.all()
        for ruleset in rulesets:
            trans_action = rule_object.get_transformation(ruleset, Transformation.ACTION)
            trans_lateral = rule_object.get_transformation(ruleset, Transformation.LATERAL)
            trans_target = rule_object.get_transformation(ruleset, Transformation.TARGET)
            all_trans = [(Transformation.ACTION, trans_action), (Transformation.LATERAL, trans_lateral), (Transformation.TARGET, trans_target)]

            for key, value in all_trans:
                if value not in rulesets_res[key]:
                    rulesets_res[key][value] = 0
                rulesets_res[key][value] += 1 

                if value:
                    rulesets_ids.append(ruleset.id)
                    current_trans[key] = value

                # Case 1: One transfo on all rulesets
                # Case 2: one transfo on n rulesets on x. x-n rulesets without transfo (None)
                if len(rulesets) == rulesets_res[key][value] or \
                        (None in rulesets_res[key] and
                         len(rulesets) == rulesets_res[key][value] + rulesets_res[key][None]):
                    if value:
                        initial[key.value] = current_trans[key].value

        # Case 3: differents transformations are applied on n rulesets
        for key, dict_val in rulesets_res.iteritems():
            for val in dict_val.iterkeys():

                if len(rulesets) == rulesets_res[key][val] or \
                        (None in rulesets_res[key] and
                         len(rulesets) == rulesets_res[key][val] + rulesets_res[key][None]):
                    pass
                else:
                    initial[key.value] = 'category'
                    if 'rulesets' in initial:
                        del initial['rulesets']

        form = RuleTransformForm(
                initial=initial,
                instance=rule_object)

    category_transforms = []
    ruleset_transforms = []
    rulesets = Ruleset.objects.all()

    for ruleset in rulesets:
        trans_cats_values = []
        trans_rulesets_values = []
        for trans_key in (Transformation.ACTION, Transformation.LATERAL, Transformation.TARGET):
            trans_cat_value = rule_object.category.get_transformation(ruleset, key=trans_key)
            trans_ruleset_value = ruleset.get_transformation(key=trans_key)

            if trans_cat_value:
                trans_cats_values.append('%s: %s' % (trans_key.name.title(), trans_cat_value.name.title()))

            if trans_ruleset_value:
                trans_rulesets_values.append('%s: %s' % (trans_key.name.title(), trans_ruleset_value.name.title()))

        if len(trans_cats_values) > 0:
            category_transforms.append({'category': rule_object.category, 'trans': " | ".join(trans_cats_values)})

        if len(trans_rulesets_values) > 0:
            ruleset_transforms.append({'ruleset': ruleset, 'trans': " | ".join(trans_rulesets_values)})

    context = {'rulesets': rulesets, 'rule': rule_object, 'form': form, 'category_transforms': category_transforms, 'ruleset_transforms': ruleset_transforms}
    return scirius_render(request, 'rules/edit_rule.html', context)


def transform_category(request, cat_id):
    cat_object = get_object_or_404(Category, pk=cat_id)

    if not request.user.is_staff:
        context = { 'category': cat_object, 'error': 'Unsufficient permissions' }
        return scirius_render(request, 'rules/category.html', context)
        
    if request.method == 'POST': # If the form has been submitted...
        form = CategoryTransformForm(request.POST)
        if form.is_valid(): # All validation rules pass
            rulesets = form.cleaned_data['rulesets']

            for ruleset in rulesets:
                form_action_trans = Transformation.ActionTransfoType(form.cleaned_data["action"])
                form_lateral_trans = Transformation.LateralTransfoType(form.cleaned_data["lateral"])
                form_target_trans = Transformation.TargetTransfoType(form.cleaned_data["target"])

                for form_trans in (form_action_trans, form_lateral_trans, form_target_trans):
                    (TYPE, NONE, LOOP) = (None, None, None)

                    # Remove all transformations
                    if form_trans == form_action_trans:
                        TYPE = Transformation.ACTION
                        NONE = Transformation.A_NONE
                        LOOP = (Transformation.A_DROP, Transformation.A_REJECT, Transformation.A_FILESTORE, Transformation.A_BYPASS)
                        RULESET_DEFAULT = Transformation.A_RULESET_DEFAULT

                    if form_trans == form_lateral_trans:
                        TYPE = Transformation.LATERAL
                        NONE = Transformation.L_NO
                        LOOP = (Transformation.L_AUTO, Transformation.L_YES, Transformation.L_NO) 
                        RULESET_DEFAULT = Transformation.L_RULESET_DEFAULT

                    if form_trans == form_target_trans:
                        TYPE = Transformation.TARGET
                        NONE = Transformation.T_NONE
                        LOOP = (Transformation.T_SOURCE, Transformation.T_DESTINATION, Transformation.T_AUTO)
                        RULESET_DEFAULT = Transformation.T_RULESET_DEFAULT

                    trans = cat_object.get_transformation(ruleset, key=TYPE)

                    if form_trans == RULESET_DEFAULT:
                        cat_object.suppress_transformation(ruleset, key=TYPE)
                        continue

                    for _trans in LOOP:
                        if _trans == form_trans:
                            continue

                        if cat_object.is_transformed(ruleset, key=TYPE, value=_trans):
                            cat_object.toggle_transformation(ruleset, key=TYPE, value=_trans)

                    # Enable new transformation
                    if form_trans != trans:
                        cat_object.toggle_transformation(ruleset, key=TYPE, value=form_trans)
                        UserAction.create(
                                action_type='transform_category',
                                comment=form.cleaned_data['comment'],
                                user=request.user,
                                transformation='%s: %s' % (TYPE.value.title(), form_trans.value.title()),
                                category=cat_object,
                                ruleset=ruleset
                        )
                    elif trans:
                        UserAction.create(
                                action_type='transform_category',
                                comment=form.cleaned_data['comment'],
                                user=request.user,
                                transformation='%s: %s' % (TYPE.value.title(), trans.value.title()),
                                category=cat_object,
                                ruleset=ruleset
                        )

            return redirect(cat_object)
    else:
        rulesets_ids = []
        current_trans = {
                Transformation.ACTION: Transformation.A_RULESET_DEFAULT,
                Transformation.LATERAL: Transformation.L_RULESET_DEFAULT,
                Transformation.TARGET: Transformation.T_RULESET_DEFAULT
        }

        rulesets_res = {
                Transformation.ACTION: {},
                Transformation.LATERAL: {},
                Transformation.TARGET: {},
        }

        initial = {'action': current_trans[Transformation.ACTION].value,
                   'lateral': current_trans[Transformation.LATERAL].value,
                   'target': current_trans[Transformation.TARGET].value,
                   'rulesets': rulesets_ids
                   }

        rulesets = Ruleset.objects.all()
        for ruleset in rulesets:
            trans_action = cat_object.get_transformation(ruleset, Transformation.ACTION)
            trans_lateral = cat_object.get_transformation(ruleset, Transformation.LATERAL)
            trans_target = cat_object.get_transformation(ruleset, Transformation.TARGET)
            all_trans = [(Transformation.ACTION, trans_action), (Transformation.LATERAL, trans_lateral), (Transformation.TARGET, trans_target)]

            for key, value in all_trans:
                if value not in rulesets_res[key]:
                    rulesets_res[key][value] = 0
                rulesets_res[key][value] += 1

                if value:
                    rulesets_ids.append(ruleset.id)
                    current_trans[key] = value

                # Case 1: One transfo on all rulesets
                # Case 2: one transfo on n rulesets on x. x-n rulesets without transfo (None)
                if len(rulesets) == rulesets_res[key][value] or \
                        (None in rulesets_res[key] and
                         len(rulesets) == rulesets_res[key][value] + rulesets_res[key][None]):
                    if value:
                        initial[key.value] = current_trans[key].value

        # Case 3: differents transformations are applied on n rulesets
        for key, dict_val in rulesets_res.iteritems():
            for val in dict_val.iterkeys():

                if len(rulesets) == rulesets_res[key][val] or \
                        (None in rulesets_res[key] and
                         len(rulesets) == rulesets_res[key][val] + rulesets_res[key][None]):
                    pass
                else:
                    initial[key.value] = 'none'
                    if 'rulesets' in initial:
                        del initial['rulesets']

        form = CategoryTransformForm(initial=initial)

    ruleset_transforms = []
    rulesets = Ruleset.objects.all()

    for ruleset in rulesets:
        trans_values = []
        for trans_key in (Transformation.ACTION, Transformation.LATERAL, Transformation.TARGET):
            trans_value = ruleset.get_transformation(key=trans_key)
            if trans_value:
                trans_values.append('%s: %s' % (trans_key.name.title(), trans_value.name.title()))

        if len(trans_values) > 0:
            ruleset_transforms.append({'ruleset': ruleset, 'trans': " | ".join(trans_values)})

    context = {'rulesets': rulesets, 'category': cat_object, 'form': form, 'ruleset_transforms': ruleset_transforms}
    return scirius_render(request, 'rules/edit_rule.html', context)

def switch_rule(request, rule_id, operation = 'disable'):
    rule_object = get_object_or_404(Rule, sid=rule_id)

    if not request.user.is_staff:
        context = { 'rule': rule_object, 'operation': operation, 'error': 'Unsufficient permissions' }
        return scirius_render(request, 'rules/disable_rule.html', context)
        
    if request.method == 'POST': # If the form has been submitted...
        form = RulesetSuppressForm(request.POST)
        if form.is_valid(): # All validation rules pass
            rulesets = form.cleaned_data['rulesets']
            for ruleset in rulesets:
                if operation == 'disable':
                    rule_object.disable(ruleset, user = request.user, comment=form.cleaned_data['comment'])
                elif operation == 'enable':
                    rule_object.enable(ruleset, user = request.user, comment=form.cleaned_data['comment'])
                ruleset.save()
            return redirect(rule_object)
    else:
        form = RulesetSuppressForm()

    context = { 'rule': rule_object, 'form': form }
    rulesets = Ruleset.objects.all()
    for ruleset in rulesets:
        ruleset.deps_rules = rule_object.get_dependant_rules(ruleset)
    context['rulesets'] = rulesets
    context['operation'] = operation
    return scirius_render(request, 'rules/disable_rule.html', context)

def disable_rule(request, rule_id):
    return switch_rule(request, rule_id)

def enable_rule(request, rule_id):
    return switch_rule(request, rule_id, operation='enable')

def test_rule(request, rule_id, ruleset_id, key = 'pk'):
    rule_object = get_object_or_404(Rule, pk=rule_id)
    ruleset = get_object_or_404(Ruleset, pk=ruleset_id)
    ret = rule_object.test(ruleset)
    return HttpResponse(json.dumps(ret), content_type="application/json")

def delete_alerts(request, rule_id):
    rule_object = get_object_or_404(Rule, sid=rule_id)

    if not request.user.is_staff:
        context = { 'object': rule, 'error': 'Unsufficient permissions' }
        context['comment_form'] = CommentForm()
        return scirius_render(request, 'rules/delete_alerts.html', context)

    if request.method == 'POST': # If the form has been submitted...
        form = CommentForm(request.POST)
        if form.is_valid():
            if hasattr(Probe.common, 'es_delete_alerts_by_sid'):
                Probe.common.es_delete_alerts_by_sid(rule_id, request=request)
            else:
                result = es_delete_alerts_by_sid(rule_id)
                if result.has_key('status') and result['status'] != 200:
                    context = { 'object': rule_object, 'error': result['msg'] }
                    try:
                        context['probes'] = map(lambda x: '"' +  x + '"', Probe.models.get_probe_hostnames())
                    except:
                        pass
                    context['comment_form'] = CommentForm()
                    return scirius_render(request, 'rules/delete_alerts.html', context)
            messages.add_message(request, messages.INFO, "Events deletion may be in progress, graphics and stats could be not in sync.");
            UserAction.create(
                    action_type='delete_alerts',
                    comment=form.cleaned_data['comment'],
                    user=request.user,
                    rule=rule_object
            )
        return redirect(rule_object)
    else:
        context = {'object': rule_object }
        context['comment_form'] = CommentForm()
        try:
            context['probes'] = map(lambda x: '"' +  x + '"', Probe.models.get_probe_hostnames())
        except:
            pass
        return scirius_render(request, 'rules/delete_alerts.html', context)

def comment_rule(request, rule_id):
    rule_object = get_object_or_404(Rule, sid=rule_id)

    if request.method == 'POST': # If the form has been submitted...
        if request.user.is_staff:
            form = RuleCommentForm(request.POST)
            if form.is_valid():
                UserAction.create(
                        action_type='comment_rule',
                        comment=form.cleaned_data['comment'],
                        user=request.user,
                        rule=rule_object
                )
    return redirect(rule_object)

def toggle_availability(request, rule_id):
    rule_object = get_object_or_404(Rule, sid=rule_id)

    if not request.user.is_staff:
        context = { 'object': rule, 'error': 'Unsufficient permissions' }
        return scirius_render(request, 'rules/rule.html', context)

    if not request.method == 'POST':
        context = { 'object': rule, 'error': 'Invalid action' }
        return scirius_render(request, 'rules/rule.html', context)

    rule_object.toggle_availability()

    UserAction.create(
            action_type='toggle_availability',
            user=request.user,
            rule=rule_object
    )

    return redirect(rule_object)

def threshold_rule(request, rule_id):
    rule_object = get_object_or_404(Rule, sid=rule_id)

    if not request.user.is_staff:
        context = { 'object': rule, 'error': 'Unsufficient permissions' }
        return scirius_render(request, 'rules/rule.html', context)

    if request.method == 'POST': # If the form has been submitted...
        action_type = 'create_threshold'

        if request.POST.has_key('threshold_type'):
            if request.POST['threshold_type'] == 'threshold':
                form = AddRuleThresholdForm(request.POST)
            else:
                form = AddRuleSuppressForm(request.POST)
                action_type = 'suppress_rule'
        else:
            context = {'rule': rule_object, 'form': form, 'error': 'Invalid form, threshold type is missing'}

            if request.POST['threshold_type'] == 'suppress':
                context['type'] = 'suppress'
            else:
                context['type'] = 'threshold'
            return scirius_render(request, 'rules/add_threshold.html', context)
        if form.is_valid():
            rulesets = form.cleaned_data['rulesets']
            for ruleset in rulesets:
                threshold = form.save(commit=False)
                threshold.rule = rule_object
                threshold.ruleset = ruleset
                threshold.pk = None
                threshold.save()

                UserAction.create(
                        action_type=action_type,
                        comment=form.cleaned_data['comment'],
                        user=request.user,
                        rule=rule_object,
                        threshold=threshold,
                        ruleset=ruleset
                )

            return redirect(rule_object)
        else:
            context = {'rule': rule_object, 'form': form, 'error': 'Could not create threshold'}
            if request.POST['threshold_type'] == 'suppress':
                context['type'] = 'suppress'
            else:
                context['type'] = 'threshold'
            return scirius_render(request, 'rules/add_threshold.html', context)
    data = { 'gid': 1, 'count': 1, 'seconds': 60, 'type': 'limit', 'rule': rule_object, 'ruleset': 1 }
    if request.GET.__contains__('action'):
        data['threshold_type'] = request.GET.get('action', 'suppress')
    if request.GET.__contains__('net'):
        data['net'] = request.GET.get('net', None)
    if request.GET.__contains__('dir'):
        direction = request.GET.get('dir', 'both')
        if direction == 'src':
            direction = 'by_src'
        elif direction == 'dest':
            direction = 'by_dst'
        data['track_by'] = direction

    if data.has_key('track_by'):
        containers = []
        pth = Threshold(rule = rule_object, track_by = data['track_by'], threshold_type = data['threshold_type'])
        if data.has_key('net'):
            pth.net = data['net']
        thresholds = Threshold.objects.filter(rule = rule_object)
        for threshold in thresholds:
            if threshold.contain(pth):
                containers.append(threshold)
                break
        if len(containers) == 0:
            containers = None
        else:
            if data['threshold_type'] == 'threshold':
                containers = RuleThresholdTable(containers)
            else:
                containers = RuleSuppressTable(containers)
            tables.RequestConfig(request).configure(containers)
        if thresholds:
            thresholds = ThresholdTable(thresholds)
            tables.RequestConfig(request).configure(thresholds)
    else:
        containers = None
        thresholds = None
        
    context = {'rule': rule_object, 'thresholds': thresholds, 'containers': containers }
    if data['threshold_type'] == 'suppress':
        context['form'] = AddRuleSuppressForm(initial=data)
        context['type'] = 'suppress'
    else:
        context['form'] = AddRuleThresholdForm(initial=data)
        context['type'] = 'threshold'
    return scirius_render(request, 'rules/add_threshold.html', context)

def disable_category(request, cat_id, operation = 'suppress'):
    cat_object = get_object_or_404(Category, id=cat_id)

    if not request.user.is_staff:
        context = { 'category': cat_object, 'error': 'Unsufficient permissions', 'operation': operation }
        return scirius_render(request, 'rules/disable_category.html', context)

    if request.method == 'POST': # If the form has been submitted...
        form = RulesetSuppressForm(request.POST)
        if form.is_valid(): # All validation rules pass
            rulesets = form.cleaned_data['rulesets']
            for ruleset in rulesets:
                if operation == 'suppress':
                    cat_object.disable(ruleset, user = request.user, comment=form.cleaned_data['comment'])
                elif operation == 'enable':
                    cat_object.enable(ruleset, user = request.user, comment=form.cleaned_data['comment'])
            return redirect(cat_object)
    else:
        form = RulesetSuppressForm()
    context = { 'category': cat_object, 'form': form, 'operation': operation }
    return scirius_render(request, 'rules/disable_category.html', context)

def enable_category(request, cat_id):
    return disable_category(request, cat_id, operation='enable')

def update_source(request, source_id):
    src = get_object_or_404(Source, pk=source_id)

    if not request.user.is_staff:
        return redirect(src)

    if request.method != 'POST': # If the form has been submitted...
        if request.is_ajax():
            data = {}
            data['status'] = False
            data['errors'] = "Invalid method for page"
            return HttpResponse(json.dumps(data), content_type="application/json")
        return source(request, source_id, error="Invalid method for page")

    try:
        if hasattr(Probe.common, 'update_source'):
            return Probe.common.update_source(request, src)
        src.update()
    except Exception, errors:
        if request.is_ajax():
            data = {}
            data['status'] = False
            data['errors'] = str(errors)
            return HttpResponse(json.dumps(data), content_type="application/json")
        if isinstance(errors, (IOError, OSError)):
            _msg = 'Can not fetch data'
        elif isinstance(errors, ValidationError):
            _msg = 'Source is invalid'
        elif isinstance(errors, SuspiciousOperation):
            _msg = 'Source is not correct'
        else:
            _msg = 'Error updating source'
        msg = '%s: %s' % (_msg, errors)
        return source(request, source_id, error=msg)

    if request.is_ajax():
        data = {}
        data['status'] = True
        data['redirect'] = True
        return HttpResponse(json.dumps(data), content_type="application/json")

    supdate = SourceUpdate.objects.filter(source = src).order_by('-created_date')
    if len(supdate) == 0:
        return redirect(src)
    return redirect('changelog_source', source_id = source_id)

def activate_source(request, source_id, ruleset_id):

    if not request.user.is_staff:
        return HttpResponse(json.dumps(False), content_type="application/json")

    if request.method != 'POST': # If the form has been submitted...
        if request.is_ajax():
            data = {}
            data['status'] = False
            data['errors'] = "Invalid method for page"
            return HttpResponse(json.dumps(data), content_type="application/json")
        return source(request, source_id, error="Invalid method for page")

    src = get_object_or_404(Source, pk=source_id)
    ruleset = get_object_or_404(Ruleset, pk=ruleset_id)

    sversions  = SourceAtVersion.objects.filter(source = src, version = 'HEAD')
    if not sversions:
        return HttpResponse(json.dumps(False), content_type="application/json")

    ruleset.sources.add(sversions[0])
    for cat in Category.objects.filter(source = src):
        cat.enable(ruleset, user = request.user)

    ruleset.needs_test()
    ruleset.save()
    return HttpResponse(json.dumps(True), content_type="application/json")

def test_source(request, source_id):
    source = get_object_or_404(Source, pk=source_id)
    sourceatversion = get_object_or_404(SourceAtVersion, source=source, version = 'HEAD')
    return HttpResponse(json.dumps(sourceatversion.test()), content_type="application/json")

def build_source_diff(request, diff):
    for field in ["added", "deleted", "updated"]:
        if field == "deleted":
            diff[field] = DeletedRuleTable(diff[field])
        else:
            diff[field] = UpdateRuleTable(diff[field])
        tables.RequestConfig(request).configure(diff[field])

def changelog_source(request, source_id):
    source = get_object_or_404(Source, pk=source_id)
    supdate = SourceUpdate.objects.filter(source = source).order_by('-created_date')
    # get last for now 
    if len(supdate) == 0:
        return scirius_render(request, 'rules/source.html', { 'source': source, 'error': "No changelog" })
    changelogs = SourceUpdateTable(supdate)
    tables.RequestConfig(request).configure(changelogs)
    diff = supdate[0].diff()
    build_source_diff(request, diff)
    return scirius_render(request, 'rules/source.html', { 'source': source, 'diff': diff, 'changelogs': changelogs , 'src_update': supdate[0]})

def diff_source(request, source_id):
    source = get_object_or_404(Source, pk=source_id)
    diff = source.diff()
    return scirius_render(request, 'rules/source.html', { 'source': source, 'diff': diff })

def add_source(request):

    if not request.user.is_staff:
        return scirius_render(request, 'rules/add_source.html', { 'error': 'Unsufficient permissions' })

    if request.method == 'POST': # If the form has been submitted...
        form = AddSourceForm(request.POST, request.FILES) # A form bound to the POST data
        if form.is_valid(): # All validation rules pass
            try:
                src = Source.objects.create(name = form.cleaned_data['name'],
                        uri = form.cleaned_data['uri'],
                        authkey = form.cleaned_data['authkey'],
                        method = form.cleaned_data['method'],
                        created_date = timezone.now(),
                        datatype = form.cleaned_data['datatype'],
                        cert_verif = form.cleaned_data['cert_verif'],
                        )
                if src.method == 'local' and request.FILES.has_key('file'):
                    try:
                        src.handle_uploaded_file(request.FILES['file'])
                    except Exception, error:
                        src.delete()
                        return scirius_render(request, 'rules/add_source.html', { 'form': form, 'error': error })
            except IntegrityError, error:
                return scirius_render(request, 'rules/add_source.html', { 'form': form, 'error': error })
            try:
                ruleset_list = form.cleaned_data['rulesets']
            except:
                ruleset_list = []
            rulesets = [ ruleset.pk for ruleset in ruleset_list ]
            if len(ruleset_list):
                for ruleset in ruleset_list:
                    UserAction.create(
                            action_type='create_source',
                            comment=form.cleaned_data['comment'],
                            user=request.user,
                            source=src,
                            ruleset=ruleset
                    )

            else:
                UserAction.create(
                        action_type='create_source',
                        comment=form.cleaned_data['comment'],
                        user=request.user,
                        source=src,
                        ruleset='No Ruleset'
                )

            ruleset_list = [ '"' + ruleset.name + '"' for ruleset in ruleset_list ]
            return scirius_render(request, 'rules/add_source.html', { 'source': src,  'update': True, 'rulesets': rulesets, 'ruleset_list': ruleset_list})
    else:
        form = AddSourceForm() # An unbound form

    return scirius_render(request, 'rules/add_source.html', { 'form': form, })

def fetch_public_sources():
    proxy_params = get_system_settings().get_proxy_params()
    try:
        hdrs = { 'User-Agent': 'scirius' }
        if proxy_params:
            resp = requests.get(settings.DEFAULT_SOURCE_INDEX_URL, proxies = proxy_params, headers = hdrs)
        else:
            resp = requests.get(settings.DEFAULT_SOURCE_INDEX_URL, headers = hdrs)
        resp.raise_for_status()
    except requests.exceptions.ConnectionError, e:
        if "Name or service not known" in str(e):
            raise IOError("Connection error 'Name or service not known'")
        elif "Connection timed out" in str(e):
            raise IOError("Connection error 'Connection timed out'")
        else:
            raise IOError("Connection error '%s'" % (e))
    except requests.exceptions.HTTPError:
        if resp.status_code == 404:
            raise IOError("URL not found on server (error 404), please check URL")
        raise IOError("HTTP error %d sent by server, please check URL or server" % (resp.status_code))
    except requests.exceptions.Timeout:
        raise IOError("Request timeout, server may be down")
    except requests.exceptions.TooManyRedirects:
        raise IOError("Too many redirects, server may be broken")
    # store as sources.yaml
    if not os.path.isdir(settings.GIT_SOURCES_BASE_DIRECTORY):
        os.makedirs(settings.GIT_SOURCES_BASE_DIRECTORY)
    sources_yaml = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, 'sources.yaml') 
    with open(sources_yaml, 'w') as sfile:
        sfile.write(resp.content)


def update_public_sources(request):
    if request.user.is_staff:
        fetch_public_sources()
    return redirect('add_public_source')


def get_public_sources(force_fetch=True):
    sources_yaml = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, 'sources.yaml') 
    if not os.path.exists(sources_yaml) or force_fetch is True:
        try:
            fetch_public_sources()
        except Exception as e:
            raise Exception(e)

    public_sources = None
    with open(sources_yaml, 'r') as stream:
        # replace dash by underscode in keys
        yaml_data = re.sub(r'(\s+\w+)-(\w+):', r'\1_\2:', stream.read())
        # FIXME error handling
        public_sources = yaml.load(yaml_data)

    if public_sources['version'] != 1:
        raise Exception("Unsupported version of sources definition")

    # get list of already defined public sources
    defined_pub_source = Source.objects.exclude(public_source__isnull=True)
    added_sources = map(lambda x: x.public_source, defined_pub_source)

    for source in public_sources['sources']:
        if public_sources['sources'][source].has_key('support_url'):
            public_sources['sources'][source]['support_url_cleaned'] = public_sources['sources'][source]['support_url'].split(' ')[0]
        if public_sources['sources'][source].has_key('subscribe_url'):
            public_sources['sources'][source]['subscribe_url_cleaned'] = public_sources['sources'][source]['subscribe_url'].split(' ')[0]
        if public_sources['sources'][source]['url'].endswith('.rules'):
            public_sources['sources'][source]['datatype'] = 'sig'
        elif public_sources['sources'][source]['url'].endswith('z'):
            public_sources['sources'][source]['datatype'] = 'sigs'
        else:
            public_sources['sources'][source]['datatype'] = 'other'
        if source in added_sources:
            public_sources['sources'][source]['added'] = True
        else:
            public_sources['sources'][source]['added'] = False

    return public_sources


def add_public_source(request):
    if not request.user.is_staff:
        return scirius_render(request, 'rules/add_public_source.html', { 'error': 'Unsufficient permissions' })

    try:
        public_sources = get_public_sources()
    except Exception as e:
        return scirius_render(request, 'rules/add_public_source.html', {'error': e})

    if request.is_ajax():
        return HttpResponse(json.dumps(public_sources['sources']), content_type="application/json")
    if request.method == 'POST':
        form = AddPublicSourceForm(request.POST)
        if form.is_valid():
            source_id = form.cleaned_data['source_id']
            source = public_sources['sources'][source_id]
            source_uri = source['url']
            params = {"__version__": "4.0"}
            if form.cleaned_data.has_key('secret_code'):
                params.update({'secret-code': form.cleaned_data['secret_code']})
            source_uri = source_uri % params
            try:
                src = Source.objects.create(name = form.cleaned_data['name'],
                        uri = source_uri,
                        method = 'http',
                        created_date = timezone.now(),
                        datatype = source['datatype'],
                        cert_verif = True,
                        public_source = source_id,
                        )
            except IntegrityError, error:
                return scirius_render(request, 'rules/add_public_source.html', { 'form': form, 'error': error })
            try:
                ruleset_list = form.cleaned_data['rulesets']
            except:
                ruleset_list = []
            rulesets = [ ruleset.pk for ruleset in ruleset_list ]
            if len(ruleset_list):
                for ruleset in ruleset_list:
                    UserAction.create(
                            action_type='create_source',
                            comment=form.cleaned_data['comment'],
                            user=request.user,
                            source=src,
                            ruleset=ruleset
                    )
            else:
                UserAction.create(
                        action_type='create_source',
                        comment=form.cleaned_data['comment'],
                        user=request.user,
                        source=src,
                        ruleset='No Ruleset'
                )
            ruleset_list = [ '"' + ruleset.name + '"' for ruleset in ruleset_list ]
            return scirius_render(request, 'rules/add_public_source.html', { 'source': src,  'update': True, 'rulesets': rulesets, 'ruleset_list': ruleset_list})
        else:
            return scirius_render(request, 'rules/add_public_source.html', { 'form': form, 'error': 'form is not valid' })
        


    rulesets = Ruleset.objects.all()
    return scirius_render(request, 'rules/add_public_source.html', { 'sources': public_sources['sources'], 'rulesets': rulesets})


def edit_source(request, source_id):
    source = get_object_or_404(Source, pk=source_id)

    if not request.user.is_staff:
        return scirius_render(request, 'rules/add_source.html', { 'error': 'Unsufficient permissions' })

    if request.method == 'POST': # If the form has been submitted...
        form = SourceForm(request.POST, request.FILES, instance=source)
        try:
            if source.method == 'local' and request.FILES.has_key('file'):
                categories = Category.objects.filter(source = source)
                firstimport = False
                if not categories:
                    firstimport = True
                source.new_uploaded_file(request.FILES['file'], firstimport)

            form.save()

            if source.datatype == 'sig':
                categories = Category.objects.filter(source=source)
                firstimport = False if len(categories) > 0 else True

                if 'name' in form.changed_data and firstimport is False:
                    category = categories[0]  # sig => one2one source/category
                    category.name = '%s Sigs' % form.cleaned_data['name']
                    category.save()

            UserAction.create(
                    action_type='edit_source',
                    comment=form.cleaned_data['comment'],
                    user=request.user,
                    source=source
            )

            return redirect(source)
        except ValueError:
            pass
    else:
        form = SourceForm(instance = source)

    return scirius_render(request, 'rules/add_source.html', { 'form': form, 'source': source})

def delete_source(request, source_id):
    source = get_object_or_404(Source, pk=source_id)

    if not request.user.is_staff:
        return scirius_render(request, 'rules/delete.html', { 'object': source, 'error': 'Unsufficient permissions'})

    if request.method == 'POST': # If the form has been submitted...
        form = CommentForm(request.POST)
        if form.is_valid():
            UserAction.create(
                    action_type='delete_source',
                    comment=form.cleaned_data['comment'],
                    user=request.user,
                    source=source
            )
            source.delete()
        return redirect("/rules/source/")
    else:
        context = {'object': source, 'delfn': 'delete_source', 'form': CommentForm()}
        return scirius_render(request, 'rules/delete.html', context)

def sourceupdate(request, update_id):
    sourceupdate = get_object_or_404(SourceUpdate, pk=update_id)
    source = sourceupdate.source
    diff = sourceupdate.diff()
    build_source_diff(request, diff)
    return scirius_render(request, 'rules/source.html', { 'source': source, 'diff': diff, 'src_update': sourceupdate })

def rulesets(request):
    rulesets = Ruleset.objects.all().order_by('name')
    context = { 'rulesets': rulesets }
    return scirius_render(request, 'rules/rulesets.html', context)

def ruleset(request, ruleset_id, mode = 'struct', error = None):
    ruleset = get_object_or_404(Ruleset, pk=ruleset_id)
    if mode == 'struct':
        categories_list = {}
        sources = ruleset.sources.all()
        for sourceatversion in sources:
            cats = CategoryTable(ruleset.categories.filter(source = sourceatversion.source).order_by('name'))
            tables.RequestConfig(request,  paginate={"per_page": 15}).configure(cats)
            categories_list[sourceatversion.source.name] = cats
        context = {'ruleset': ruleset, 'categories_list': categories_list, 'sources': sources, 'mode': mode}

        # Threshold
        thresholds = Threshold.objects.filter(ruleset = ruleset, threshold_type = 'threshold')
        if thresholds:
            thresholds = RulesetThresholdTable(thresholds)
            tables.RequestConfig(request).configure(thresholds)
            context['thresholds'] = thresholds
        suppress = Threshold.objects.filter(ruleset = ruleset, threshold_type = 'suppress')
        if suppress:
            suppress = RulesetSuppressTable(suppress)
            tables.RequestConfig(request).configure(suppress)
            context['suppress'] = suppress

        # Error
        if error:
            context['error'] = error

        S_SUPPRESSED = Transformation.S_SUPPRESSED
        A_REJECT = Transformation.A_REJECT
        A_DROP = Transformation.A_DROP
        A_FILESTORE = Transformation.A_FILESTORE

        for trans in (S_SUPPRESSED, A_REJECT, A_DROP, A_FILESTORE):
            # Rules transformation
            trans_rules = ruleset.rules_transformation.filter(ruletransformation__value=trans.value).all()
            if len(trans_rules):
                trans_rules_t = RuleTable(trans_rules.order_by('sid'))
                tables.RequestConfig(request).configure(trans_rules_t)

                ctx_lb = '%s_rules' % trans.value if trans != S_SUPPRESSED else 'disabled_rules'
                context[ctx_lb] = trans_rules_t

            # Categories Transformation
            if trans != S_SUPPRESSED:  # SUPPRESSED cannot be applied on categories
                trans_categories = ruleset.categories_transformation.filter(categorytransformation__value=trans.value).all()
                if len(trans_categories):
                    trans_categories_t = CategoryTable(trans_categories.order_by('name'))
                    tables.RequestConfig(request).configure(trans_categories_t)
                    context['%s_categories' % trans.value] = trans_categories_t

    elif mode == 'display':
        rules = RuleTable(ruleset.generate())
        tables.RequestConfig(request).configure(rules)
        context = {'ruleset': ruleset, 'rules': rules, 'mode': mode}
        if error:
            context['error'] = error
    elif mode == 'export':
        file_content = ruleset.to_buffer()
        response = HttpResponse(file_content, content_type="text/plain")
        response['Content-Disposition'] = 'attachment; filename=scirius.rules'
        return response

    if hasattr(Probe.common, 'update_ruleset'):
        context['middleware_has_update'] = True
    return scirius_render(request, 'rules/ruleset.html', context)

def add_ruleset(request):
    if not request.user.is_staff:
        return scirius_render(request, 'rules/add_ruleset.html', { 'error': 'Unsufficient permissions' })

    context = {}
    if request.method == 'POST': # If the form has been submitted...
        form = RulesetForm(request.POST) # A form bound to the POST data
        if form.is_valid(): # All validation rules pass
            # Process the data in form.cleaned_data
            # ...
            try:
                ruleset = form.create_ruleset()
                UserAction.create(
                        action_type='create_ruleset',
                        comment=form.cleaned_data['comment'],
                        user=request.user,
                        ruleset=ruleset
                )

                form_action_trans = Transformation.ActionTransfoType(form.cleaned_data["action"])
                form_lateral_trans = Transformation.LateralTransfoType(form.cleaned_data["lateral"])
                form_target_trans = Transformation.TargetTransfoType(form.cleaned_data["target"])
    
                if form_action_trans != Transformation.A_NONE:
                    ruleset.set_transformation(key=Transformation.ACTION, value=form_action_trans)
                else:
                    ruleset.remove_transformation(Transformation.ACTION)

                if form_lateral_trans != Transformation.L_NO:
                    ruleset.set_transformation(key=Transformation.LATERAL, value=form_lateral_trans)
                else:
                    ruleset.remove_transformation(Transformation.LATERAL)

                if form_target_trans != Transformation.T_NONE:
                    ruleset.set_transformation(key=Transformation.TARGET, value=form_target_trans)
                else:
                    ruleset.remove_transformation(Transformation.TARGET)

            except IntegrityError, error:
                return scirius_render(request, 'rules/add_ruleset.html', {'form': form, 'error': error})

            msg = """All changes are saved. Don't forget to update the ruleset to apply the changes.
                     After the ruleset Update the changes would be updated on the probe(s) upon the next Ruleset Push"""

            messages.success(request, msg)
            return redirect(ruleset)
    else:
        initial = {'action': Transformation.A_NONE.value,
                   'lateral': Transformation.L_NO.value,
                   'target': Transformation.T_NONE.value
                   }
        form = RulesetForm(initial=initial)  # An unbound form
        missing = dependencies_check(Ruleset)
        if missing:
            context['missing'] = missing
    context['form'] = form

    return scirius_render(request, 'rules/add_ruleset.html', context)

def update_ruleset(request, ruleset_id):
    rset = get_object_or_404(Ruleset, pk=ruleset_id)

    if not request.user.is_staff:
        return redirect(rset)

    if request.method != 'POST': # If the form has been submitted...
        if request.is_ajax():
            data = {}
            data['status'] = False
            data['errors'] = "Invalid method for page"
            return HttpResponse(json.dumps(data), content_type="application/json")
        return ruleset(rset, ruleset_id, error="Invalid method for page")

    if hasattr(Probe.common, 'update_ruleset'):
        return Probe.common.update_ruleset(request, rset)
    try:
        rset.update()
    except IOError, errors:
        error="Can not fetch data: %s" % (errors)
        if request.is_ajax():
            return HttpResponse(json.dumps({'status': False, 'errors': error}), content_type="application/json")
        return ruleset(request, ruleset_id, error)
    if request.is_ajax():
        return HttpResponse(json.dumps({'status': True, 'redirect': True}), content_type="application/json")
    return redirect('changelog_ruleset', ruleset_id = ruleset_id)

def changelog_ruleset(request, ruleset_id):
    ruleset = get_object_or_404(Ruleset, pk=ruleset_id)
    diff = ruleset.diff()
    for key in diff:
        cdiff = diff[key]
        build_source_diff(request, cdiff)
        diff[key] = cdiff
    return scirius_render(request, 'rules/ruleset.html', { 'ruleset': ruleset, 'diff': diff, 'mode': 'changelog'})

def test_ruleset(request, ruleset_id):
    ruleset = get_object_or_404(Ruleset, pk=ruleset_id)
    return HttpResponse(json.dumps(ruleset.test()), content_type="application/json")

def edit_ruleset(request, ruleset_id):
    ruleset = get_object_or_404(Ruleset, pk=ruleset_id)

    if not request.user.is_staff:
        return scirius_render(request, 'rules/edit_ruleset.html', {'ruleset': ruleset, 'error': 'Unsufficient permissions'})

    # TODO: manage other types
    SUPPRESSED = Transformation.SUPPRESSED
    S_SUPPRESSED = Transformation.S_SUPPRESSED

    if request.method == 'POST': # If the form has been submitted...
        # check if this is a categories edit
        # ID is unique so we can just look by indice and add
        form = CommentForm(request.POST)
        if not form.is_valid():
            return redirect(ruleset)

        if request.POST.has_key('category'):
            category_selection = [ int(x) for x in request.POST.getlist('category_selection') ]
            # clean ruleset
            for cat in ruleset.categories.all():
                if cat.pk not in category_selection:
                    cat.disable(ruleset, user = request.user, comment=form.cleaned_data['comment'])
            # add updated entries
            for cat in category_selection:
                category = get_object_or_404(Category, pk=cat)
                if category not in ruleset.categories.all():
                    category.enable(ruleset, user = request.user, comment=form.cleaned_data['comment'])
        elif request.POST.has_key('rules'):
            for rule in request.POST.getlist('rule_selection'):
                rule_object = get_object_or_404(Rule, pk=rule)
                if rule_object in ruleset.get_transformed_rules(key=SUPPRESSED, value=S_SUPPRESSED):
                    rule_object.enable(ruleset, user = request.user, comment=form.cleaned_data['comment'])
        elif request.POST.has_key('sources'):
            source_selection = [ int(x) for x in request.POST.getlist('source_selection')]
            # clean ruleset
            for source in ruleset.sources.all():
                if source.pk not in source_selection:
                    source.disable(ruleset, user = request.user, comment=form.cleaned_data['comment'])
            # add new entries
            for src in source_selection:
                source = get_object_or_404(SourceAtVersion, pk=src)
                if source not in ruleset.sources.all():
                    source.enable(ruleset, user = request.user, comment=form.cleaned_data['comment'])
        else:
            form = RulesetEditForm(request.POST, instance=ruleset)

            if form.is_valid():
                UserAction.create(
                        action_type='edit_ruleset',
                        comment=form.cleaned_data['comment'],
                        user=request.user,
                        ruleset=ruleset
                )

                form.save()

                form_action_trans = Transformation.ActionTransfoType(form.cleaned_data["action"])
                form_lateral_trans = Transformation.LateralTransfoType(form.cleaned_data["lateral"])
                form_target_trans = Transformation.TargetTransfoType(form.cleaned_data["target"])
    
                if form_action_trans != Transformation.A_NONE:
                    ruleset.set_transformation(key=Transformation.ACTION, value=form_action_trans)
                else:
                    ruleset.remove_transformation(Transformation.ACTION)

                if form_lateral_trans != Transformation.L_NO:
                    ruleset.set_transformation(key=Transformation.LATERAL, value=form_lateral_trans)
                else:
                    ruleset.remove_transformation(Transformation.LATERAL)

                if form_target_trans != Transformation.T_NONE:
                    ruleset.set_transformation(key=Transformation.TARGET, value=form_target_trans)
                else:
                    ruleset.remove_transformation(Transformation.TARGET)
            else:
                return scirius_render(request, 'rules/edit_ruleset.html', {'ruleset': ruleset, 'error': 'Invalid form.', 'form': form})

        msg = """All changes are saved. Don't forget to update the ruleset to apply the changes.
                 After the ruleset Update the changes would be updated on the probe(s) upon the next Ruleset Push"""

        messages.success(request, msg)

        return redirect(ruleset)
    else:
        cats_selection = []
        categories_list = {}
        sources = ruleset.sources.all()
        ruleset_cats = ruleset.categories.all()
        for sourceatversion in sources:
            src_cats = Category.objects.filter(source = sourceatversion.source)
            for pcats in src_cats:
                if pcats in ruleset_cats:
                    cats_selection.append(str(pcats.id))
            cats = EditCategoryTable(src_cats)
            tables.RequestConfig(request,paginate = False).configure(cats)
            categories_list[sourceatversion.source.name] = cats
        rules = EditRuleTable(ruleset.get_transformed_rules(key=SUPPRESSED, value=S_SUPPRESSED))
        tables.RequestConfig(request, paginate = False).configure(rules)

        context = {'ruleset': ruleset,  'categories_list': categories_list, 'sources': sources, 'rules': rules, 'cats_selection': ", ".join(cats_selection) }
        if request.GET.has_key('mode'):
            context['mode'] = request.GET['mode']
            context['form'] = CommentForm()
            if context['mode'] == 'sources':
                all_sources = SourceAtVersion.objects.all()
                sources_selection = []
                for source in sources:
                    sources_selection.append(source.pk)
                sources_list = EditSourceAtVersionTable(all_sources)
                tables.RequestConfig(request, paginate = False).configure(sources_list)
                context['sources_list'] = sources_list
                context['sources_selection'] = sources_selection
        else:
            initial = {'action': Transformation.A_NONE.value,
                       'lateral': Transformation.L_NO.value,
                       'target': Transformation.T_NONE.value
                       }
            trans_action = RulesetTransformation.objects.filter(key=Transformation.ACTION.value, ruleset_transformation=ruleset)
            if len(trans_action) > 0:
                initial['action'] = trans_action[0].value

            trans_lateral = RulesetTransformation.objects.filter(key=Transformation.LATERAL.value, ruleset_transformation=ruleset)
            if len(trans_lateral) > 0:
                initial['lateral'] = trans_lateral[0].value

            trans_target = RulesetTransformation.objects.filter(key=Transformation.TARGET.value, ruleset_transformation=ruleset)
            if len(trans_target) > 0:
                initial['target'] = trans_target[0].value

            # trans_action = CategoryTransformation.objects.filter(key=Transformation.ACTION.value, ruleset=ruleset)
            # if len(trans_action) > 0:
            #     initial['action'] = trans_action[0].value

            # trans_lateral = CategoryTransformation.objects.filter(key=Transformation.LATERAL.value, ruleset=ruleset)
            # if len(trans_lateral) > 0:
            #     initial['lateral'] = trans_lateral[0].value

            # trans_target = CategoryTransformation.objects.filter(key=Transformation.TARGET.value, ruleset=ruleset)
            # if len(trans_action) > 0:
            #     initial['target'] = trans_target[0].value

            context['form'] = RulesetEditForm(instance=ruleset, initial=initial)
        return scirius_render(request, 'rules/edit_ruleset.html', context)


def ruleset_add_supprule(request, ruleset_id):
    ruleset = get_object_or_404(Ruleset, pk=ruleset_id)

    if not request.user.is_staff:
        context = { 'ruleset': ruleset, 'error': 'Unsufficient permissions' }
        return scirius_render(request, 'rules/search_rule.html', context)

    if request.method == 'POST': # If the form has been submitted...
        if request.POST.has_key('search'):
            #FIXME Protection on SQL injection ?
            rules = EditRuleTable(Rule.objects.filter(content__icontains=request.POST['search']))
            tables.RequestConfig(request).configure(rules)
            context = { 'ruleset': ruleset, 'rules': rules, 'form': CommentForm() }
            return scirius_render(request, 'rules/search_rule.html', context)
        elif request.POST.has_key('rule_selection'):
            form = CommentForm(request.POST)
            if not form.is_valid():
                return redirect(ruleset)
            for rule in request.POST.getlist('rule_selection'):
                rule_object = get_object_or_404(Rule, pk=rule)
                rule_object.disable(ruleset, user = request.user, comment = form.cleaned_data['comment'])
            ruleset.save()
        return redirect(ruleset)

    rules = EditRuleTable(Rule.objects.all())
    tables.RequestConfig(request).configure(rules)
    context = {'ruleset': ruleset, 'rules': rules, 'form': CommentForm()}
    return scirius_render(request, 'rules/search_rule.html', context)


def delete_ruleset(request, ruleset_id):
    ruleset = get_object_or_404(Ruleset, pk=ruleset_id)

    if not request.user.is_staff:
        context = { 'object': ruleset, 'error': 'Unsufficient permissions', 'form': CommentForm()  }
        return scirius_render(request, 'rules/delete.html', context)

    if request.method == 'POST': # If the form has been submitted...
        form = CommentForm(request.POST)
        if form.is_valid():
            UserAction.create(
                    action_type='delete_ruleset',
                    comment=form.cleaned_data['comment'],
                    user=request.user,
                    ruleset=ruleset
            )
            ruleset.delete()
        return redirect("/rules/ruleset/")
    else:
        context = {'object': ruleset, 'delfn': 'delete_ruleset', 'form': CommentForm()}
        return scirius_render(request, 'rules/delete.html', context)

def copy_ruleset(request, ruleset_id):
    ruleset = get_object_or_404(Ruleset, pk=ruleset_id)

    if not request.user.is_staff:
        context = { 'object': ruleset, 'error': 'Unsufficient permissions' }
        return scirius_render(request, 'rules/copy_ruleset.html', context)

    if request.method == 'POST': # If the form has been submitted...
        form = RulesetCopyForm(request.POST) # A form bound to the POST data
        if form.is_valid(): # All validation rules pass
            copy = ruleset.copy(form.cleaned_data['name'])
            UserAction.create(
                    action_type='copy_ruleset',
                    comment=form.cleaned_data['comment'],
                    user=request.user,
                    ruleset=ruleset
            )
            return redirect(copy)
    else:
        form = RulesetCopyForm()
    context = {'object': ruleset , 'form': form}
    return scirius_render(request, 'rules/copy_ruleset.html', context)

def system_settings(request):
    if not request.user.is_staff:
        context = { 'error': 'Unsufficient permissions' }
        return scirius_render(request, 'rules/system_settings.html', context)

    gsettings = get_system_settings()
    main_form = SystemSettingsForm(instance = gsettings)
    kibana_form = KibanaDataForm()
    context = {
        'form_id': 'main',
        'main_form': main_form,
        'kibana_form': kibana_form,
    }

    if request.method == 'POST':
        form_id = request.POST.get('form_id', None)

        if form_id == 'main':
            main_form = SystemSettingsForm(request.POST, instance = gsettings)
            context['main_form'] = main_form
            if main_form.is_valid():
                main_form.save()
                context['success'] = "All changes saved."
            else:
                context['error'] = "Invalid form."

        elif form_id == 'es':
            es_data = ESData()
            try:
                es_data.es_clear()
                context['success'] = 'Done'
            except ConnectionError as e:
                context['error'] = 'Could not connect to Elasticsearch'
            except Exception as e:
                context['error'] = 'Clearing failed: %s' % e

        elif form_id == 'kibana':
            es_data = ESData()
            if 'export' in request.POST:
                tar_name, tar_file = es_data.kibana_export()

                with open(tar_file, 'rb') as f:
                    content = f.read()

                os.unlink(tar_file)
                response = HttpResponse(content, content_type='application/x-bzip2')
                response['Content-Disposition'] = 'attachment; filename="%s"' % tar_name
                return response
            elif 'import' in request.POST:
                form = KibanaDataForm(request.POST, request.FILES)
                if form.is_valid() and 'file' in request.FILES:
                    try:
                        count = es_data.kibana_import_fileobj(request.FILES['file'])
                        context['success'] = 'Successfully imported %i objects' % count
                    except Exception, e:
                        context['error'] = 'Import failed: %s' % e
                else:
                    context['error'] = 'Please provide a dashboard archive'
            elif 'clear' in request.POST:
                try:
                    es_data.kibana_clear()
                    context['success'] = 'Done'
                except Exception, e:
                    context['error'] = 'Clearing failed: %s' % e
            elif 'reset' in request.POST:
                try:
                    es_data.kibana_reset()
                    context['success'] = 'Done'
                except Exception, e:
                    context['error'] = 'Reset failed: %s' % e
            else:
                context['error'] = 'Invalid operation'
        else:
            context['error'] = "Invalid form id."

        if form_id is not None:
            context['form_id'] = form_id

        UserAction.create(
                action_type='system_settings',
                user=request.user,
        )
    context['global_settings'] = get_system_settings()
    return scirius_render(request, 'rules/system_settings.html', context)

def info(request):
    data = {'status': 'green'}
    if request.GET.__contains__('query'):
        info = Probe.common.Info()
        query = request.GET.get('query', 'status')
        if query == 'status':
            data = { 'running': info.status() }
        elif query == 'disk':
            data = info.disk()
        elif query == 'memory':
            data = info.memory()
        elif query == 'cpu':
            data = info.cpu()
    return HttpResponse(json.dumps(data),
                        content_type="application/json")

def threshold(request, threshold_id):
    threshold = get_object_or_404(Threshold, pk=threshold_id)
    threshold.rule.highlight_content = SuriHTMLFormat(threshold.rule.content)
    threshold.highlight_content = SuriHTMLFormat(str(threshold))
    context = { 'threshold': threshold }
    return scirius_render(request, 'rules/threshold.html', context)

def edit_threshold(request, threshold_id):
    threshold = get_object_or_404(Threshold, pk=threshold_id)
    rule = threshold.rule
    ruleset = threshold.ruleset

    if not request.user.is_staff:
        return redirect(threshold)

    if request.method == 'POST': # If the form has been submitted...
        form = EditThresholdForm(request.POST, instance=threshold) # A form bound to the POST data
        if form.is_valid(): # All validation rules pass
            form.save()
            UserAction.create(
                    action_type='edit_threshold',
                    comment=form.cleaned_data['comment'],
                    user=request.user,
                    rule=rule,
                    threshold=threshold,
                    ruleset=ruleset
            )
            return redirect(threshold)
        else:
            context = {'threshold': threshold, 'form': form, 'error': 'Invalid form'}            
            return scirius_render(request, 'rules/edit_threshold.html', context)
    else:
        form = EditThresholdForm(instance=threshold)
        context = { 'threshold': threshold, 'form': form }
        return scirius_render(request, 'rules/edit_threshold.html', context)

def delete_threshold(request, threshold_id):
    threshold = get_object_or_404(Threshold, pk=threshold_id)
    ruleset = threshold.ruleset
    rule = threshold.rule
    if not request.user.is_staff:
        context = { 'object': threshold, 'error': 'Unsufficient permissions', 'form': CommentForm() }
        return scirius_render(request, 'rules/delete.html', context)

    if request.method == 'POST': # If the form has been submitted...
        form = CommentForm(request.POST)
        if form.is_valid():
            action_type = 'delete_suppress_rule' if threshold.threshold_type == 'suppress' else 'delete_threshold'
            UserAction.create(
                    action_type=action_type,
                    comment=form.cleaned_data['comment'],
                    user=request.user,
                    rule=rule,
                    threshold=threshold,
                    ruleset=ruleset
            )
            threshold.delete()
        return redirect(ruleset)
    else:
        context = {'object': threshold, 'delfn': 'delete_threshold', 'form': CommentForm() }
        return scirius_render(request, 'rules/delete.html', context)

def history(request):
    history = UserAction.objects.all().order_by('-date')
    # useractions = HistoryTable(history)
    # tables.RequestConfig(request).configure(useractions)

    context = {'history': history[:50]}
    return scirius_render(request, 'rules/history.html', context)

def delete_comment(request, comment_id):
    ua = get_object_or_404(UserAction, pk=comment_id, action="comment", user = request.user)
    ua.delete()
    data = {'status': 'OK'}
    return HttpResponse(json.dumps(data), content_type="application/json")

def hunt(request):
    context = { }
    return scirius_render(request, 'rules/hunt.html', context)
