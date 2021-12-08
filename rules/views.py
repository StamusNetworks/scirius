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

import re
import os
import yaml
import json
from datetime import date

from django.shortcuts import get_object_or_404, redirect
from django.utils import timezone
from django.http import HttpResponse, HttpResponseServerError, JsonResponse
from django.db import IntegrityError
from django.conf import settings
from django.core.exceptions import SuspiciousOperation, ValidationError, PermissionDenied
from django.contrib import messages
from django.contrib.auth.decorators import permission_required
from django.urls import reverse
from elasticsearch.exceptions import ConnectionError as ESConnectionError
import django_tables2 as tables

from csp.decorators import csp

from scirius.utils import scirius_render, scirius_listing, RequestsWrapper

from rules.es_data import ESData
from rules.models import Ruleset, Source, SourceUpdate, Category, Rule, dependencies_check, get_system_settings
from rules.models import Threshold, Transformation, RulesetTransformation, UserAction, reset_es_address, SourceAtVersion
from rules.tables import UpdateRuleTable, DeletedRuleTable, ThresholdTable, SourceUpdateTable

from rules.es_graphs import ESError, ESRulesStats, ESFieldStatsAsTable, ESSidByHosts, ESIndices, ESDeleteAlertsBySid
from rules.es_graphs import get_es_major_version, reset_es_version

from .tables import RuleTable, CategoryTable, RulesetTable, CategoryRulesetTable, RuleHostTable, ESIndexessTable
from .tables import RuleThresholdTable, RuleSuppressTable, RulesetThresholdTable, RulesetSuppressTable
from .tables import EditCategoryTable, EditRuleTable, EditSourceAtVersionTable
from .forms import RuleCommentForm, RuleTransformForm, CategoryTransformForm, RulesetSuppressForm, CommentForm
from .forms import AddRuleThresholdForm, AddRuleSuppressForm, AddSourceForm, AddPublicSourceForm, SourceForm
from .forms import RulesetForm, RulesetEditForm, RulesetCopyForm, SystemSettingsForm, KibanaDataForm, EditThresholdForm, PoliciesForm
from .suripyg import SuriHTMLFormat

PROBE = __import__(settings.RULESET_MIDDLEWARE)


# Create your views here.
def index(request):
    ruleset_list = Ruleset.objects.all().order_by('-created_date')[:5]
    source_list = Source.objects.all().order_by('-created_date')[:5]
    context = {'ruleset_list': ruleset_list,
               'source_list': source_list}
    try:
        context['probes'] = ['"' + x + '"' for x in PROBE.models.get_probe_hostnames()]
    except:
        pass
    return scirius_render(request, 'rules/index.html', context)


@permission_required('rules.ruleset_policy_view', raise_exception=True)
def search(request):
    context = {}
    length = 0
    rules_width = 4
    search = None
    if request.method == 'POST':
        if 'search' in request.POST:
            search = request.POST['search']
            request.GET = request.GET.copy()
            request.GET.update({'search': search})
    elif request.method == 'GET':
        if 'search' in request.GET:
            search = request.GET['search']
    if search:
        rules = Rule.objects.filter(content__icontains=search)
        if len(rules) > 0:
            length += len(rules)
            rules = RuleTable(rules)
            tables.RequestConfig(request).configure(rules)
        else:
            rules = None
        categories_ = Category.objects.filter(name__icontains=search)
        if len(categories_) > 0:
            length += len(categories_)
            categories_ = CategoryTable(categories_)
            tables.RequestConfig(request).configure(categories_)
        else:
            rules_width += 4
            categories_ = None
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
        categories_ = None
        rulesets = None

    context = {
        'rules': rules,
        'rules_width': rules_width,
        'categories': categories_,
        'rulesets': rulesets,
        'motif': search,
        'length': length
    }
    return scirius_render(request, 'rules/search.html', context)


@permission_required('rules.source_view', raise_exception=True)
def sources(request):
    from scirius.utils import get_middleware_module
    sources = get_middleware_module('common').get_sources().order_by('name')

    for source_ in sources:
        if source_.cats_count == 0:
            source_.build_counters()

    context = {'sources': sources}
    return scirius_render(request, 'rules/sources.html', context)


@permission_required('rules.ruleset_policy_view', raise_exception=True)
def source(request, source_id, error=None, update=False, activate=False, rulesets=None):
    source = get_object_or_404(Source, pk=source_id)
    cats = CategoryTable(Category.objects.filter(source=source).order_by('name'))
    tables.RequestConfig(request).configure(cats)
    context = {'source': source, 'categories': cats,
               'update': update, 'activate': activate, 'rulesets': rulesets}
    if error:
        context['error'] = error
    if hasattr(PROBE.common, 'update_source'):
        context['middleware_has_update'] = True

    return scirius_render(request, 'rules/source.html', context)


@permission_required('rules.ruleset_policy_view', raise_exception=True)
def categories(request):
    assocfn = {
        'Categories': {
            'table': CategoryTable,
            'manage_links': {},
            'action_links': {}
        }
    }

    return scirius_listing(request, Category, assocfn)


@permission_required('rules.ruleset_policy_view', raise_exception=True)
def category(request, cat_id):
    cat = get_object_or_404(Category, pk=cat_id)
    rules = RuleTable(Rule.objects.filter(category=cat, state=True).order_by('sid'))
    tables.RequestConfig(request).configure(rules)
    commented_rules = RuleTable(Rule.objects.filter(category=cat, state=False))
    tables.RequestConfig(request).configure(commented_rules)
    category_path = [cat.source]
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
    RULE_FIELDS_MAPPING = {
        'rule_src': 'src_ip',
        'rule_dest': 'dest_ip',
        'rule_source': 'alert.source.ip',
        'rule_target': 'alert.target.ip',
        'rule_probe': settings.ELASTICSEARCH_HOSTNAME,
        'field_stats': None
    }
    context = {'es2x': get_es_major_version() >= 2}

    def check_perms(query):
        PERM_CONF_VIEW = ('indices', 'rule_probe', 'field_stats', None)
        PERM_EVENT_VIEW = ('rule_src', 'rule_dest', 'rule_source', 'rule_target')
        PERM_CONF_AND_EVENT_VIEW = ('rules', 'rule')

        if query in PERM_EVENT_VIEW:
            if not request.user.has_perm('rules.events_view'):
                raise PermissionDenied()

        if query in PERM_CONF_VIEW:
            if not request.user.has_perm('rules.configuration_view'):
                raise PermissionDenied()

        if query in PERM_CONF_AND_EVENT_VIEW:
            if not request.user.has_perm('rules.configuration_view') and not request.user.has_perm('rules.events_view'):
                raise PermissionDenied()

    if request.GET.__contains__('query'):
        query = request.GET.get('query')
        check_perms(query)
        try:
            if query == 'rules':
                rules = ESRulesStats(request).get()
                if rules is None:
                    return JsonResponse(rules)
                context['table'] = rules
                return scirius_render(request, 'rules/table.html', context)
            elif query == 'rule':
                sid = request.GET.get('sid', None)
                hosts = ESSidByHosts(request).get(sid)
                context['table'] = hosts
                return scirius_render(request, 'rules/table.html', context)
            elif query in list(RULE_FIELDS_MAPPING.keys()):
                ajax = request.GET.get('json', None)
                if ajax:
                    raise ESError('Use REST API instead.')

                if query == 'field_stats':
                    filter_ip = request.GET.get('field', 'src_ip')
                else:
                    filter_ip = RULE_FIELDS_MAPPING[query]

                sid = request.GET.get('sid', None)
                count = request.GET.get('page_size', 10)

                hosts = ESFieldStatsAsTable(request).get(
                    sid,
                    filter_ip + '.' + settings.ELASTICSEARCH_KEYWORD,
                    RuleHostTable,
                    count=count
                )
                context['table'] = hosts
                return scirius_render(request, 'rules/table.html', context)
            elif query == 'indices':
                if request.is_ajax():
                    indices = ESIndexessTable(ESIndices(request).get())
                    tables.RequestConfig(request).configure(indices)
                    context['table'] = indices
                    return scirius_render(request, 'rules/table.html', context)
                else:
                    return scirius_render(request, 'rules/elasticsearch.html', context)
            else:
                raise Exception('Query parameter not supported: %s' % query)
        except ESError as e:
            return HttpResponseServerError(str(e))
    else:
        check_perms(None)
        template = PROBE.common.get_es_template()
        return scirius_render(request, template, context)


def extract_rule_references(rule):
    references = []
    for ref in re.findall(r"reference: *(\w+), *(\S+);", rule.content):
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
    return references


@permission_required('rules.ruleset_policy_view', raise_exception=True)
def rule(request, rule_id, key='pk'):
    if request.is_ajax():
        rule = get_object_or_404(Rule, sid=rule_id)
        rule.highlight_content = SuriHTMLFormat(rule.content)
        data = {'msg': rule.msg, 'sid': rule.sid, 'content': rule.content,
                'highlight_content': rule.highlight_content}
        return JsonResponse(data)
    if key == 'pk':
        rule = get_object_or_404(Rule, pk=rule_id)
    else:
        rule = get_object_or_404(Rule, sid=rule_id)
    rule_path = [rule.category.source, rule.category]

    rule.highlight_content = SuriHTMLFormat(rule.content)
    references = extract_rule_references(rule)

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
        if Threshold.objects.filter(rule=rule, ruleset=ruleset, threshold_type='threshold'):
            threshold = True

        suppress = False
        if Threshold.objects.filter(rule=rule, ruleset=ruleset, threshold_type='suppress'):
            suppress = True

        content = rule.generate_content(ruleset)
        if content:
            content = SuriHTMLFormat(rule.generate_content(ruleset))
        ruleset_info = {'name': ruleset.name, 'pk': ruleset.pk, 'status': status,
                        'threshold': threshold, 'suppress': suppress,
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
                ruleset_info[prefix + trans.value] = True
                if content:
                    rule_transformations = True
        rulesets_status.append(ruleset_info)

    comment_form = RuleCommentForm()
    context = {
        'rule': rule,
        'history': rule.get_actions(request.user),
        'references': references,
        'object_path': rule_path,
        'rulesets': rulesets_status,
        'rule_transformations': rule_transformations,
        'comment_form': comment_form
    }

    thresholds = Threshold.objects.filter(rule=rule, threshold_type='threshold')
    if thresholds:
        thresholds = RuleThresholdTable(thresholds)
        tables.RequestConfig(request).configure(thresholds)
        context['thresholds'] = thresholds
    suppress = Threshold.objects.filter(rule=rule, threshold_type='suppress')
    if suppress:
        suppress = RuleSuppressTable(suppress)
        tables.RequestConfig(request).configure(suppress)
        context['suppress'] = suppress
    try:
        context['probes'] = ['"' + x + '"' for x in PROBE.models.get_probe_hostnames()]
    except:
        pass

    context['kibana_version'] = get_es_major_version()
    return scirius_render(request, 'rules/rule.html', context)


@permission_required('rules.ruleset_policy_edit', raise_exception=True)
def edit_rule(request, rule_id):
    rule_object = get_object_or_404(Rule, sid=rule_id)

    if request.method == 'POST':  # If the form has been submitted...
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
                        if trans is None:
                            continue

                        cat_trans = rule_object.category.get_transformation(ruleset, TYPE)
                        if cat_trans is None:
                            cat_trans = NONE

                        if trans != cat_trans:
                            UserAction.create(
                                action_type='transform_rule',
                                comment=form.cleaned_data['comment'],
                                request=request,
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
                            request=request,
                            transformation='%s: %s' % (TYPE.value.title(), form_trans.value.title()),
                            rule=rule_object,
                            ruleset=ruleset
                        )
                    elif form_trans == NONE and trans:
                        UserAction.create(
                            action_type='transform_rule',
                            comment=form.cleaned_data['comment'],
                            request=request,
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
                        (None in rulesets_res[key] and len(rulesets) == rulesets_res[key][value] + rulesets_res[key][None]):
                    if value:
                        initial[key.value] = current_trans[key].value

        # Case 3: differents transformations are applied on n rulesets
        for key, dict_val in rulesets_res.items():
            for val in dict_val.keys():

                if len(rulesets) == rulesets_res[key][val] or \
                        (None in rulesets_res[key] and len(rulesets) == rulesets_res[key][val] + rulesets_res[key][None]):
                    pass
                else:
                    initial[key.value] = 'category'
                    if 'rulesets' in initial:
                        del initial['rulesets']

        form = RuleTransformForm(
            initial=initial,
            instance=rule_object
        )

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


@permission_required('rules.ruleset_policy_view', raise_exception=True)
def transform_category(request, cat_id):
    cat_object = get_object_or_404(Category, pk=cat_id)

    if request.method == 'POST':
        form = CategoryTransformForm(request.POST, request=request)
        if form.is_valid():  # All validation rules pass
            rulesets = form.cleaned_data['rulesets']

            for ruleset in rulesets:
                form_action_trans = Transformation.ActionTransfoType(form.cleaned_data["action"])
                form_lateral_trans = Transformation.LateralTransfoType(form.cleaned_data["lateral"])
                form_target_trans = Transformation.TargetTransfoType(form.cleaned_data["target"])

                for form_trans in (form_action_trans, form_lateral_trans, form_target_trans):
                    (TYPE, LOOP) = (None, None)

                    # Remove all transformations
                    if form_trans == form_action_trans:
                        TYPE = Transformation.ACTION
                        LOOP = (Transformation.A_DROP, Transformation.A_REJECT, Transformation.A_FILESTORE, Transformation.A_BYPASS)
                        RULESET_DEFAULT = Transformation.A_RULESET_DEFAULT

                    if form_trans == form_lateral_trans:
                        TYPE = Transformation.LATERAL
                        LOOP = (Transformation.L_AUTO, Transformation.L_YES, Transformation.L_NO)
                        RULESET_DEFAULT = Transformation.L_RULESET_DEFAULT

                    if form_trans == form_target_trans:
                        TYPE = Transformation.TARGET
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
                            request=request,
                            transformation='%s: %s' % (TYPE.value.title(), form_trans.value.title()),
                            category=cat_object,
                            ruleset=ruleset
                        )
                    elif trans:
                        UserAction.create(
                            action_type='transform_category',
                            comment=form.cleaned_data['comment'],
                            request=request,
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
                        (None in rulesets_res[key] and len(rulesets) == rulesets_res[key][value] + rulesets_res[key][None]):
                    if value:
                        initial[key.value] = current_trans[key].value

        # Case 3: differents transformations are applied on n rulesets
        for key, dict_val in rulesets_res.items():
            for val in dict_val.keys():

                if len(rulesets) == rulesets_res[key][val] or \
                        (None in rulesets_res[key] and len(rulesets) == rulesets_res[key][val] + rulesets_res[key][None]):
                    pass
                else:
                    initial[key.value] = 'none'
                    if 'rulesets' in initial:
                        del initial['rulesets']

        form = CategoryTransformForm(initial=initial, request=request)

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


def switch_rule(request, rule_id, operation='disable'):
    rule_object = get_object_or_404(Rule, sid=rule_id)

    if request.method == 'POST':  # If the form has been submitted...
        form = RulesetSuppressForm(request.POST)
        if form.is_valid():  # All validation rules pass
            rulesets = form.cleaned_data['rulesets']
            for ruleset in rulesets:

                suppressed_rules = ruleset.get_transformed_rules(
                    key=Transformation.SUPPRESSED,
                    value=Transformation.S_SUPPRESSED
                ).values_list('pk', flat=True)

                if rule_object.pk not in suppressed_rules and operation == 'disable':
                    rule_object.disable(ruleset, request=request, comment=form.cleaned_data['comment'])
                elif rule_object.pk in suppressed_rules and operation == 'enable':
                    rule_object.enable(ruleset, request=request, comment=form.cleaned_data['comment'])
                ruleset.save()
            return redirect(rule_object)
    else:
        form = RulesetSuppressForm()

    context = {'rule': rule_object, 'form': form}
    rulesets = Ruleset.objects.all()
    for ruleset in rulesets:
        ruleset.deps_rules = rule_object.get_dependant_rules(ruleset)
    context['rulesets'] = rulesets
    context['operation'] = operation
    return scirius_render(request, 'rules/disable_rule.html', context)


@permission_required('rules.ruleset_policy_edit', raise_exception=True)
def disable_rule(request, rule_id):
    return switch_rule(request, rule_id)


@permission_required('rules.ruleset_policy_edit', raise_exception=True)
def enable_rule(request, rule_id):
    return switch_rule(request, rule_id, operation='enable')


@permission_required('rules.ruleset_policy_view', raise_exception=True)
def test_rule(request, rule_id, ruleset_id, key='pk'):
    rule_object = get_object_or_404(Rule, pk=rule_id)
    ruleset = get_object_or_404(Ruleset, pk=ruleset_id)
    ret = rule_object.test(ruleset)
    return JsonResponse(ret)


@permission_required('rules.events_edit', raise_exception=True)
def delete_alerts(request, rule_id):
    rule_object = get_object_or_404(Rule, sid=rule_id)

    if request.method == 'POST':  # If the form has been submitted...
        form = CommentForm(request.POST)
        if form.is_valid():
            if hasattr(PROBE.common, 'es_delete_alerts_by_sid'):
                PROBE.common.es_delete_alerts_by_sid(rule_id, request=request)
            else:
                result = ESDeleteAlertsBySid(request).get(rule_id)
                if 'status' in result and result['status'] != 200:
                    context = {'object': rule_object, 'error': result['msg']}
                    try:
                        context['probes'] = ['"' + x + '"' for x in PROBE.models.get_probe_hostnames()]
                    except:
                        pass
                    context['comment_form'] = CommentForm()
                    return scirius_render(request, 'rules/delete_alerts.html', context)

            messages.add_message(request, messages.INFO, "Events deletion may be in progress, graphics and stats could be not in sync.")
            UserAction.create(
                action_type='delete_alerts',
                comment=form.cleaned_data['comment'],
                request=request,
                rule=rule_object
            )
        return redirect(rule_object)
    else:
        context = {'object': rule_object}
        context['comment_form'] = CommentForm()
        try:
            context['probes'] = ['"' + x + '"' for x in PROBE.models.get_probe_hostnames()]
        except:
            pass
        return scirius_render(request, 'rules/delete_alerts.html', context)


@permission_required('rules.ruleset_policy_edit', raise_exception=True)
def comment_rule(request, rule_id):
    rule_object = get_object_or_404(Rule, sid=rule_id)

    if request.method == 'POST':  # If the form has been submitted...
        form = RuleCommentForm(request.POST)
        if form.is_valid():
            UserAction.create(
                action_type='comment_rule',
                comment=form.cleaned_data['comment'],
                request=request,
                rule=rule_object
            )
    return redirect(rule_object)


@permission_required('rules.ruleset_policy_edit', raise_exception=True)
def toggle_availability(request, rule_id):
    rule_object = get_object_or_404(Rule, sid=rule_id)

    if not request.method == 'POST':
        context = {'object': rule, 'error': 'Invalid action'}
        return scirius_render(request, 'rules/rule.html', context)

    rule_object.toggle_availability()

    UserAction.create(
        action_type='toggle_availability',
        request=request,
        rule=rule_object
    )

    return redirect(rule_object)


@permission_required('rules.ruleset_policy_edit', raise_exception=True)
def threshold_rule(request, rule_id):
    rule_object = get_object_or_404(Rule, sid=rule_id)

    if request.method == 'POST':  # If the form has been submitted...
        action_type = 'create_threshold'

        if 'threshold_type' in request.POST:
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
                    request=request,
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

    data = {'gid': 1, 'count': 1, 'seconds': 60, 'type': 'limit', 'rule': rule_object, 'ruleset': 1}
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

    if 'track_by' in data:
        containers = []
        pth = Threshold(rule=rule_object, track_by=data['track_by'], threshold_type=data['threshold_type'])

        if 'net' in data:
            pth.net = data['net']
        thresholds = Threshold.objects.filter(rule=rule_object)

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

    context = {'rule': rule_object, 'thresholds': thresholds, 'containers': containers}
    if data['threshold_type'] == 'suppress':
        context['form'] = AddRuleSuppressForm(initial=data)
        context['type'] = 'suppress'
    else:
        context['form'] = AddRuleThresholdForm(initial=data)
        context['type'] = 'threshold'
    return scirius_render(request, 'rules/add_threshold.html', context)


@permission_required('rules.ruleset_policy_edit', raise_exception=True)
def disable_category(request, cat_id, operation='suppress'):
    cat_object = get_object_or_404(Category, id=cat_id)

    if request.method == 'POST':  # If the form has been submitted...
        form = RulesetSuppressForm(request.POST)
        if form.is_valid():  # All validation rules pass
            rulesets = form.cleaned_data['rulesets']
            for ruleset in rulesets:
                if operation == 'suppress':
                    cat_object.disable(ruleset, request=request, comment=form.cleaned_data['comment'])
                elif operation == 'enable':
                    cat_object.enable(ruleset, request=request, comment=form.cleaned_data['comment'])
            return redirect(cat_object)
    else:
        form = RulesetSuppressForm()
    context = {'category': cat_object, 'form': form, 'operation': operation}
    return scirius_render(request, 'rules/disable_category.html', context)


@permission_required('rules.ruleset_policy_edit', raise_exception=True)
def enable_category(request, cat_id):
    return disable_category(request, cat_id, operation='enable')


@permission_required('rules.ruleset_update_push', raise_exception=True)
def update_source(request, source_id):
    src = get_object_or_404(Source, pk=source_id)

    if request.method != 'POST':  # If the form has been submitted...
        if request.is_ajax():
            data = {}
            data['status'] = False
            data['errors'] = "Invalid method for page"
            return JsonResponse(data)
        return source(request, source_id, error="Invalid method for page")

    try:
        if hasattr(PROBE.common, 'update_source'):
            return PROBE.common.update_source(request, src)
        src.update()
    except Exception as errors:
        if request.is_ajax():
            data = {}
            data['status'] = False
            data['errors'] = str(errors)
            return JsonResponse(data)
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
        return JsonResponse(data)

    supdate = SourceUpdate.objects.filter(source=src).order_by('-created_date')
    if len(supdate) == 0:
        return redirect(src)

    return redirect('changelog_source', source_id=source_id)


@permission_required('rules.source_edit', raise_exception=True)
def activate_source(request, source_id, ruleset_id):

    if request.method != 'POST':  # If the form has been submitted...
        if request.is_ajax():
            data = {}
            data['status'] = False
            data['errors'] = "Invalid method for page"
            return JsonResponse(data)
        return source(request, source_id, error="Invalid method for page")

    src = get_object_or_404(Source, pk=source_id)
    ruleset = get_object_or_404(Ruleset, pk=ruleset_id)

    sversions = SourceAtVersion.objects.filter(source=src, version='HEAD')
    if not sversions:
        return JsonResponse(False, safe=False)

    ruleset.sources.add(sversions[0])
    for cat in Category.objects.filter(source=src):
        cat.enable(ruleset, request=request)

    ruleset.needs_test()
    ruleset.save()
    return JsonResponse(True, safe=False)


@permission_required('rules.source_view', raise_exception=True)
def test_source(request, source_id):
    source = get_object_or_404(Source, pk=source_id)
    sourceatversion = get_object_or_404(SourceAtVersion, source=source, version='HEAD')
    return JsonResponse(sourceatversion.test())


def build_source_diff(request, diff):
    for field in ["added", "deleted", "updated"]:
        if field == "deleted":
            diff[field] = DeletedRuleTable(diff[field])
        else:
            diff[field] = UpdateRuleTable(diff[field])
        tables.RequestConfig(request).configure(diff[field])


@permission_required('rules.source_view', raise_exception=True)
def changelog_source(request, source_id):
    source = get_object_or_404(Source, pk=source_id)
    supdate = SourceUpdate.objects.filter(source=source).order_by('-created_date')
    # get last for now
    if len(supdate) == 0:
        return scirius_render(request, 'rules/source.html', {'source': source, 'error': "No changelog"})
    changelogs = SourceUpdateTable(supdate)
    tables.RequestConfig(request).configure(changelogs)
    diff = supdate[0].diff()
    build_source_diff(request, diff)
    return scirius_render(request, 'rules/source.html', {'source': source, 'diff': diff, 'changelogs': changelogs, 'src_update': supdate[0]})


@permission_required('rules.source_view', raise_exception=True)
def diff_source(request, source_id):
    source = get_object_or_404(Source, pk=source_id)
    diff = source.diff()
    return scirius_render(request, 'rules/source.html', {'source': source, 'diff': diff})


@permission_required('rules.source_edit', raise_exception=True)
def add_source(request):
    if request.method == 'POST':  # If the form has been submitted...
        form = AddSourceForm(request.POST, request.FILES)  # A form bound to the POST data
        if form.is_valid():  # All validation rules pass
            try:
                src = Source.objects.create(
                    name=form.cleaned_data['name'],
                    uri=form.cleaned_data['uri'],
                    authkey=form.cleaned_data['authkey'],
                    method=form.cleaned_data['method'],
                    created_date=timezone.now(),
                    datatype=form.cleaned_data['datatype'],
                    cert_verif=form.cleaned_data['cert_verif'],
                    use_iprep=form.cleaned_data['use_iprep']
                )

                if src.method == 'local':
                    try:
                        if 'file' not in request.FILES:
                            form.add_error('file', 'This field is required.')
                            raise Exception('A source file is required')
                        src.handle_uploaded_file(request.FILES['file'])
                    except Exception as error:
                        if isinstance(error, ValidationError):
                            if hasattr(error, 'error_dict'):
                                error = ', '.join(['%s: %s' % (key, val) for key, val in error.message_dict.items()])
                            elif hasattr(error, 'error_list'):
                                error = ', '.join(error.messages)
                            else:
                                error = str(error)
                        src.delete()
                        return scirius_render(request, 'rules/add_source.html', {'form': form, 'error': error})

            except IntegrityError as error:
                return scirius_render(request, 'rules/add_source.html', {'form': form, 'error': error})
            try:
                ruleset_list = form.cleaned_data['rulesets']
            except:
                ruleset_list = []

            rulesets = [ruleset.pk for ruleset in ruleset_list]
            if len(ruleset_list):
                for ruleset in ruleset_list:
                    UserAction.create(
                        action_type='create_source',
                        comment=form.cleaned_data['comment'],
                        request=request,
                        source=src,
                        ruleset=ruleset
                    )

            else:
                UserAction.create(
                    action_type='create_source',
                    comment=form.cleaned_data['comment'],
                    request=request,
                    source=src,
                    ruleset='No Ruleset'
                )

            ruleset_list = ['"' + ruleset.name + '"' for ruleset in ruleset_list]
            return scirius_render(
                request,
                'rules/add_source.html',
                {'source': src, 'update': True, 'rulesets': rulesets, 'ruleset_list': ruleset_list}
            )
    else:
        form = AddSourceForm()  # An unbound form

    return scirius_render(request, 'rules/add_source.html', {'form': form})


def fetch_public_sources():
    resp = RequestsWrapper().get(url=settings.DEFAULT_SOURCE_INDEX_URL)

    # store as sources.yaml
    if not os.path.isdir(settings.GIT_SOURCES_BASE_DIRECTORY):
        os.makedirs(settings.GIT_SOURCES_BASE_DIRECTORY)

    sources_yaml = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, 'sources.yaml')
    with open(sources_yaml, 'wb') as sfile:
        sfile.write(resp.content)


@permission_required('rules.source_edit', raise_exception=True)
def update_public_sources(request):
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
    with open(sources_yaml, 'r', encoding='utf-8') as stream:
        buf = stream.read()
        # replace dash by underscode in keys
        yaml_data = re.sub(r'(\s+\w+)-(\w+):', r'\1_\2:', buf)
        # FIXME error handling
        public_sources = yaml.safe_load(yaml_data)

    if public_sources['version'] != 1:
        raise Exception("Unsupported version of sources definition")

    # get list of already defined public sources
    defined_pub_source = Source.objects.exclude(public_source__isnull=True)
    added_sources = [x.public_source for x in defined_pub_source]

    for source_ in public_sources['sources']:
        if 'support_url' in public_sources['sources'][source_]:
            public_sources['sources'][source_]['support_url_cleaned'] = public_sources['sources'][source_]['support_url'].split(' ')[0]
        if 'subscribe_url' in public_sources['sources'][source_]:
            public_sources['sources'][source_]['subscribe_url_cleaned'] = public_sources['sources'][source_]['subscribe_url'].split(' ')[0]
        if public_sources['sources'][source_]['url'].endswith('.rules'):
            public_sources['sources'][source_]['datatype'] = 'sig'
        elif public_sources['sources'][source_]['url'].endswith('z'):
            public_sources['sources'][source_]['datatype'] = 'sigs'
        else:
            public_sources['sources'][source_]['datatype'] = 'other'
        if source_ in added_sources:
            public_sources['sources'][source_]['added'] = True
        else:
            public_sources['sources'][source_]['added'] = False

    return public_sources


@permission_required('rules.source_edit', raise_exception=True)
def add_public_source(request):
    try:
        public_sources = get_public_sources()
    except Exception as e:
        return scirius_render(request, 'rules/add_public_source.html', {'error': e})

    if request.is_ajax():
        return JsonResponse(public_sources['sources'])
    if request.method == 'POST':
        form = AddPublicSourceForm(request.POST)
        if form.is_valid():
            source_id = form.cleaned_data['source_id']
            source = public_sources['sources'][source_id]
            source_uri = source['url']
            params = {"__version__": "5.0"}
            if 'secret_code' in form.cleaned_data:
                params.update({'secret-code': form.cleaned_data['secret_code']})
            source_uri = source_uri % params
            try:
                src = Source.objects.create(
                    name=form.cleaned_data['name'],
                    uri=source_uri,
                    method='http',
                    created_date=timezone.now(),
                    datatype=source['datatype'],
                    cert_verif=True,
                    public_source=source_id,
                    use_iprep=form.cleaned_data['use_iprep']
                )
            except IntegrityError as error:
                return scirius_render(request, 'rules/add_public_source.html', {'form': form, 'error': error})
            try:
                ruleset_list = form.cleaned_data['rulesets']
            except:
                ruleset_list = []
            rulesets = [ruleset.pk for ruleset in ruleset_list]
            if len(ruleset_list):
                for ruleset in ruleset_list:
                    UserAction.create(
                        action_type='create_source',
                        comment=form.cleaned_data['comment'],
                        request=request,
                        source=src,
                        ruleset=ruleset
                    )
            else:
                UserAction.create(
                    action_type='create_source',
                    comment=form.cleaned_data['comment'],
                    request=request,
                    source=src,
                    ruleset='No Ruleset'
                )
            ruleset_list = ['"' + ruleset.name + '"' for ruleset in ruleset_list]
            return scirius_render(
                request,
                'rules/add_public_source.html',
                {'source': src, 'update': True, 'rulesets': rulesets, 'ruleset_list': ruleset_list}
            )
        else:
            return scirius_render(
                request,
                'rules/add_public_source.html',
                {'form': form, 'error': 'form is not valid'}
            )

    rulesets = Ruleset.objects.all()
    return scirius_render(
        request,
        'rules/add_public_source.html',
        {'sources': public_sources['sources'], 'rulesets': rulesets}
    )


@permission_required('rules.source_edit', raise_exception=True)
def edit_source(request, source_id):
    source = get_object_or_404(Source, pk=source_id)

    if request.method == 'POST':  # If the form has been submitted...
        prev_uri = source.uri
        form = SourceForm(request.POST, request.FILES, instance=source)
        try:
            if source.method == 'local' and 'file' in request.FILES:
                source.new_uploaded_file(request.FILES['file'])

            form.save()

            # do a soft reset of rules in the source if URL changes
            if source.method == 'http' and source.uri != prev_uri:
                Rule.objects.filter(category__source=source).update(rev=0)
                source.version = 1
                source.save()

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
                request=request,
                source=source
            )

            return redirect(source)
        except Exception as e:
            if isinstance(e, ValidationError):
                e = e.message
            return scirius_render(
                request,
                'rules/add_source.html',
                {'form': form, 'source': source, 'error': e}
            )
    else:
        form = SourceForm(instance=source)

    return scirius_render(
        request,
        'rules/add_source.html',
        {'form': form, 'source': source}
    )


@permission_required('rules.source_edit', raise_exception=True)
def delete_source(request, source_id):
    source = get_object_or_404(Source, pk=source_id)

    if request.method == 'POST':  # If the form has been submitted...
        form = CommentForm(request.POST)
        if form.is_valid():
            UserAction.create(
                action_type='delete_source',
                comment=form.cleaned_data['comment'],
                request=request,
                source=source
            )
            source.delete()
        return redirect("/rules/source/")
    else:
        context = {'object': source, 'delfn': 'delete_source', 'form': CommentForm()}
        return scirius_render(request, 'rules/delete.html', context)


@permission_required('rules.source_edit', raise_exception=True)
def sourceupdate(request, update_id):
    sourceupdate = get_object_or_404(SourceUpdate, pk=update_id)
    source = sourceupdate.source
    diff = sourceupdate.diff()
    build_source_diff(request, diff)
    return scirius_render(
        request,
        'rules/source.html',
        {'source': source, 'diff': diff, 'src_update': sourceupdate}
    )


@permission_required('rules.source_view', raise_exception=True)
def rulesets(request):
    rulesets = Ruleset.objects.all().order_by('name')
    for ruleset in rulesets:
        ruleset.number_of_rules()
    context = {'rulesets': rulesets}
    return scirius_render(request, 'rules/rulesets.html', context)


@permission_required('rules.ruleset_policy_view', raise_exception=True)
def ruleset(request, ruleset_id, mode='struct', error=None):
    ruleset = get_object_or_404(Ruleset, pk=ruleset_id)
    if mode == 'struct':
        categories_list = {}
        sources = ruleset.sources.all()
        for sourceatversion in sources:
            cats = CategoryTable(ruleset.categories.filter(source=sourceatversion.source).order_by('name'))
            tables.RequestConfig(request, paginate={"per_page": 15}).configure(cats)
            categories_list[sourceatversion.source.name] = cats

        context = {'ruleset': ruleset, 'categories_list': categories_list, 'sources': sources, 'mode': mode}

        # Threshold
        thresholds = Threshold.objects.filter(ruleset=ruleset, threshold_type='threshold')
        if thresholds:
            thresholds = RulesetThresholdTable(thresholds)
            tables.RequestConfig(request).configure(thresholds)
            context['thresholds'] = thresholds

        suppress = Threshold.objects.filter(ruleset=ruleset, threshold_type='suppress')
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
                trans_categories = ruleset.categories_transformation.filter(
                    categorytransformation__value=trans.value
                ).all()

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

    if hasattr(PROBE.common, 'update_ruleset'):
        context['middleware_has_update'] = True
    return scirius_render(request, 'rules/ruleset.html', context)


@permission_required('rules.source_edit', raise_exception=True)
def add_ruleset(request):
    from scirius.utils import get_middleware_module

    extra_form = get_middleware_module('common').extra_ruleset_form(request)

    context = {}
    if extra_form:
        context = extra_form.get_context()
        context['extra_form'] = extra_form

    if request.method == 'POST':  # If the form has been submitted...
        form = RulesetForm(request.POST)  # A form bound to the POST data
        context['form'] = form

        if form.is_valid() and (extra_form is None or extra_form.is_valid()):  # All validation rules pass

            ruleset = extra_form.cleaned_data['ruleset'] if extra_form else None
            try:
                if ruleset is None:
                    ruleset = Ruleset.create_ruleset(
                        name=form.cleaned_data['name'],
                        sources=form.cleaned_data['sources'].values_list('pk', flat=True),
                        activate_categories=form.cleaned_data['activate_categories']
                    )

                if extra_form:
                    extra_form.run()

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

            except IntegrityError as error:
                if ruleset:
                    Ruleset.objects.filter(pk=ruleset.pk).delete()

                context.update({'form': form, 'error': error})
                return scirius_render(request, 'rules/add_ruleset.html', context)

            UserAction.create(
                action_type='create_ruleset',
                comment=form.cleaned_data['comment'],
                request=request,
                ruleset=ruleset
            )

            msg = """All changes are saved. Don't forget to update the ruleset to apply the changes.
                     After the ruleset Update the changes would be updated on the probe(s) upon the next Ruleset Push"""

            messages.success(request, msg)
            return redirect(ruleset)
        else:
            if form.errors:
                context['error'] = repr(form.errors)

        if extra_form.data.get('ruleset', False):
            Ruleset.objects.filter(pk=extra_form.data['ruleset']).delete()
    else:
        initial = {'action': Transformation.A_NONE.value,
                   'lateral': Transformation.L_AUTO.value,
                   'target': Transformation.T_AUTO.value
                   }
        form = RulesetForm(initial=initial)  # An unbound form
        context['form'] = form

        missing = dependencies_check(Ruleset)
        if missing:
            context['missing'] = missing

    return scirius_render(request, 'rules/add_ruleset.html', context)


@permission_required('rules.ruleset_update_push', raise_exception=True)
def update_ruleset(request, ruleset_id):
    rset = get_object_or_404(Ruleset, pk=ruleset_id)
    if request.method != 'POST':  # If the form has been submitted...
        if request.is_ajax():
            data = {}
            data['status'] = False
            data['errors'] = "Invalid method for page"
            return JsonResponse(data)
        return ruleset(rset, ruleset_id, error="Invalid method for page")

    if hasattr(PROBE.common, 'update_ruleset'):
        return PROBE.common.update_ruleset(request, rset)
    try:
        rset.update()
    except IOError as errors:
        error = "Can not fetch data: %s" % (errors)
        if request.is_ajax():
            return JsonResponse({'status': False, 'errors': error})
        return ruleset(request, ruleset_id, error)
    if request.is_ajax():
        return JsonResponse({'status': True, 'redirect': True})
    return redirect('changelog_ruleset', ruleset_id=ruleset_id)


@permission_required('rules.source_view', raise_exception=True)
def changelog_ruleset(request, ruleset_id):
    from scirius.utils import get_middleware_module

    ruleset = get_object_or_404(Ruleset, pk=ruleset_id)
    return get_middleware_module('common').changelog_ruleset(request, ruleset)


@permission_required('rules.source_view', raise_exception=True)
def test_ruleset(request, ruleset_id):
    ruleset = get_object_or_404(Ruleset, pk=ruleset_id)
    return JsonResponse(ruleset.test())


def edit_ruleset(request, ruleset_id):
    user = request.user
    if not user.has_perm('rules.ruleset_policy_edit') and not user.has_perm('rules.source_edit'):
        raise PermissionDenied()

    ruleset = get_object_or_404(Ruleset, pk=ruleset_id)

    # TODO: manage other types
    SUPPRESSED = Transformation.SUPPRESSED
    S_SUPPRESSED = Transformation.S_SUPPRESSED

    if request.method == 'POST':  # If the form has been submitted...
        # check if this is a categories edit
        # ID is unique so we can just look by indice and add
        form = CommentForm(request.POST)
        if not form.is_valid():
            return redirect(ruleset)

        if 'category' in request.POST:
            if not user.has_perm('rules.ruleset_policy_edit'):
                raise PermissionDenied()

            category_selection = [int(x) for x in request.POST.getlist('category_selection')]
            # clean ruleset
            for cat in ruleset.categories.all():
                if cat.pk not in category_selection:
                    cat.disable(ruleset, request=request, comment=form.cleaned_data['comment'])

            # add updated entries
            for cat in category_selection:
                category = get_object_or_404(Category, pk=cat)
                if category not in ruleset.categories.all():
                    category.enable(ruleset, request=request, comment=form.cleaned_data['comment'])

        elif 'rules' in request.POST:
            if not user.has_perm('rules.ruleset_policy_edit'):
                raise PermissionDenied()

            for rule in request.POST.getlist('rule_selection'):
                rule_object = get_object_or_404(Rule, pk=rule)
                if rule_object in ruleset.get_transformed_rules(key=SUPPRESSED, value=S_SUPPRESSED):
                    rule_object.enable(ruleset, request=request, comment=form.cleaned_data['comment'])

        elif 'sources' in request.POST:
            if not user.has_perm('rules.source_edit'):
                raise PermissionDenied()

            source_selection = [int(x) for x in request.POST.getlist('source_selection')]
            # clean ruleset
            for source_ in ruleset.sources.all():
                if source_.pk not in source_selection:
                    source_.disable(ruleset, request=request, comment=form.cleaned_data['comment'])

            # add new entries
            for src in source_selection:
                source = get_object_or_404(SourceAtVersion, pk=src)
                if source not in ruleset.sources.all():
                    source.enable(ruleset, request=request, comment=form.cleaned_data['comment'])
        else:
            form = RulesetEditForm(request.POST, instance=ruleset, request=request)

            if form.is_valid():
                UserAction.create(
                    action_type='edit_ruleset',
                    comment=form.cleaned_data['comment'],
                    request=request,
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
                return scirius_render(
                    request,
                    'rules/edit_ruleset.html',
                    {'ruleset': ruleset, 'error': 'Invalid form.', 'form': form}
                )

        msg = """All changes are saved. Don't forget to update the ruleset to apply the changes.
                 After the ruleset Update the changes would be updated on the probe(s) upon the next Ruleset Push"""

        messages.success(request, msg)

        return redirect(ruleset)
    else:
        mode = request.GET.get('mode', None)

        if mode == 'sources':
            if not user.has_perm('rules.source_edit'):
                raise PermissionDenied()
        elif mode in ('categories', 'rules'):
            if not user.has_perm('rules.ruleset_policy_edit'):
                raise PermissionDenied()

        cats_selection = []
        categories_list = {}
        sources = ruleset.sources.all()
        ruleset_cats = ruleset.categories.all()
        for sourceatversion in sources:
            src_cats = Category.objects.filter(source=sourceatversion.source)
            for pcats in src_cats:
                if pcats in ruleset_cats:
                    cats_selection.append(str(pcats.id))

            cats = EditCategoryTable(src_cats)
            tables.RequestConfig(request, paginate=False).configure(cats)
            categories_list[sourceatversion.source.name] = cats
        rules = EditRuleTable(ruleset.get_transformed_rules(key=SUPPRESSED, value=S_SUPPRESSED))
        tables.RequestConfig(request, paginate=False).configure(rules)

        context = {
            'ruleset': ruleset,
            'categories_list': categories_list,
            'sources': sources,
            'rules': rules,
            'cats_selection': ", ".join(cats_selection)
        }

        if 'mode' in request.GET:
            context['mode'] = mode
            context['form'] = CommentForm()
            if context['mode'] == 'sources':
                if not user.has_perm('rules.source_edit'):
                    raise PermissionDenied()

                from scirius.utils import get_middleware_module
                all_sources = SourceAtVersion.objects.exclude(
                    source__datatype__in=get_middleware_module('common').custom_source_datatype(True)
                )

                sources_selection = []
                for source_ in sources:
                    sources_selection.append(source_.pk)

                sources_list = EditSourceAtVersionTable(all_sources)
                tables.RequestConfig(request, paginate=False).configure(sources_list)
                context['sources_list'] = sources_list
                context['sources_selection'] = sources_selection
        else:
            initial = {'action': Transformation.A_NONE.value,
                       'lateral': Transformation.L_NO.value,
                       'target': Transformation.T_NONE.value
                       }
            trans_action = RulesetTransformation.objects.filter(
                key=Transformation.ACTION.value,
                ruleset_transformation=ruleset
            )

            if len(trans_action) > 0:
                initial['action'] = trans_action[0].value

            trans_lateral = RulesetTransformation.objects.filter(
                key=Transformation.LATERAL.value,
                ruleset_transformation=ruleset
            )

            if len(trans_lateral) > 0:
                initial['lateral'] = trans_lateral[0].value

            trans_target = RulesetTransformation.objects.filter(
                key=Transformation.TARGET.value,
                ruleset_transformation=ruleset
            )

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

            context['form'] = RulesetEditForm(instance=ruleset, initial=initial, request=request)
        return scirius_render(request, 'rules/edit_ruleset.html', context)


@permission_required('rules.ruleset_policy_edit', raise_exception=True)
def ruleset_add_supprule(request, ruleset_id):
    ruleset = get_object_or_404(Ruleset, pk=ruleset_id)
    if request.method == 'POST':  # If the form has been submitted...
        if 'search' in request.POST:
            # FIXME Protection on SQL injection ?
            rules = EditRuleTable(Rule.objects.filter(content__icontains=request.POST['search']))
            tables.RequestConfig(request).configure(rules)
            context = {'ruleset': ruleset, 'rules': rules, 'form': CommentForm()}
            return scirius_render(request, 'rules/search_rule.html', context)
        elif 'rule_selection' in request.POST:
            form = CommentForm(request.POST)
            if not form.is_valid():
                return redirect(ruleset)
            for rule in request.POST.getlist('rule_selection'):
                rule_object = get_object_or_404(Rule, pk=rule)
                rule_object.disable(ruleset, request=request, comment=form.cleaned_data['comment'])
            ruleset.save()
        return redirect(ruleset)

    rules = EditRuleTable(Rule.objects.all())
    tables.RequestConfig(request).configure(rules)
    context = {'ruleset': ruleset, 'rules': rules, 'form': CommentForm()}
    return scirius_render(request, 'rules/search_rule.html', context)


@permission_required('rules.source_edit', raise_exception=True)
def delete_ruleset(request, ruleset_id):
    ruleset = get_object_or_404(Ruleset, pk=ruleset_id)

    if request.method == 'POST':  # If the form has been submitted...
        form = CommentForm(request.POST)
        if form.is_valid():
            UserAction.create(
                action_type='delete_ruleset',
                comment=form.cleaned_data['comment'],
                request=request,
                ruleset=ruleset
            )
            ruleset.delete()
        return redirect("/rules/ruleset/")
    else:
        context = {'object': ruleset, 'delfn': 'delete_ruleset', 'form': CommentForm()}
        return scirius_render(request, 'rules/delete.html', context)


@permission_required('rules.source_edit', raise_exception=True)
def copy_ruleset(request, ruleset_id):
    ruleset = get_object_or_404(Ruleset, pk=ruleset_id)
    if request.method == 'POST':  # If the form has been submitted...
        form = RulesetCopyForm(request.POST)  # A form bound to the POST data
        if form.is_valid():  # All validation rules pass
            copy = ruleset.copy(form.cleaned_data['name'])
            UserAction.create(
                action_type='copy_ruleset',
                comment=form.cleaned_data['comment'],
                request=request,
                ruleset=ruleset
            )
            return redirect(copy)
    else:
        form = RulesetCopyForm()
    context = {'object': ruleset, 'form': form}
    return scirius_render(request, 'rules/copy_ruleset.html', context)


@permission_required('rules.configuration_view', raise_exception=True)
def system_settings(request):
    gsettings = get_system_settings()
    main_form = SystemSettingsForm(instance=gsettings, request=request)
    kibana_form = KibanaDataForm()

    context = {
        'form_id': 'main',
        'main_form': main_form,
        'kibana_form': kibana_form,
    }

    if request.method == 'POST':
        form_id = request.POST.get('form_id', None)
        comment = {'comment': request.POST.get('comment', None)}

        if form_id == 'main':
            main_form = SystemSettingsForm(request.POST, instance=gsettings, request=request)
            context['main_form'] = main_form
            if main_form.is_valid():
                main_form.save()
                reset_es_address()
                reset_es_version()
                context['success'] = "All changes saved."
            else:
                context['error'] = "Invalid form."

        elif form_id == 'es':
            es_data = ESData()
            try:
                es_data.es_clear()
                context['success'] = 'Done'
            except ESConnectionError:
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
                    except Exception as e:
                        context['error'] = 'Import failed: %s' % e
                else:
                    context['error'] = 'Please provide a dashboard archive'
            elif 'clear' in request.POST:
                try:
                    es_data.kibana_clear()
                    context['success'] = 'Done'
                except Exception as e:
                    context['error'] = 'Clearing failed: %s' % e
            elif 'reset' in request.POST:
                try:
                    es_data.kibana_reset()
                    context['success'] = 'Done'
                except Exception as e:
                    context['error'] = 'Reset failed: %s' % e
            else:
                context['error'] = 'Invalid operation'
        else:
            context['error'] = "Invalid form id."

        if form_id is not None:
            context['form_id'] = form_id

        comment_form = CommentForm(comment)
        comment_form.is_valid()
        UserAction.create(
            action_type='system_settings',
            comment=comment_form.cleaned_data['comment'],
            request=request,
        )
    context['global_settings'] = get_system_settings()
    return scirius_render(request, 'rules/system_settings.html', context)


def info(request):
    data = {'status': 'green'}
    if request.GET.__contains__('query'):
        info = PROBE.common.Info()
        query = request.GET.get('query', 'status')
        if query == 'status':
            data = {'running': info.status()}
        elif query == 'disk':
            data = info.disk()
        elif query == 'memory':
            data = info.memory()
        elif query == 'used_memory':
            data = info.used_memory()
        elif query == 'cpu':
            data = info.cpu()
    return JsonResponse(data, safe=False)


@permission_required('rules.ruleset_policy_view', raise_exception=True)
def threshold(request, threshold_id):
    threshold = get_object_or_404(Threshold, pk=threshold_id)
    threshold.rule.highlight_content = SuriHTMLFormat(threshold.rule.content)
    threshold.highlight_content = SuriHTMLFormat(str(threshold))
    context = {'threshold': threshold}
    return scirius_render(request, 'rules/threshold.html', context)


@permission_required('rules.ruleset_policy_edit', raise_exception=True)
def edit_threshold(request, threshold_id):
    threshold = get_object_or_404(Threshold, pk=threshold_id)
    rule = threshold.rule
    ruleset = threshold.ruleset

    if request.method == 'POST':  # If the form has been submitted...
        form = EditThresholdForm(request.POST, instance=threshold)  # A form bound to the POST data
        if form.is_valid():  # All validation rules pass
            form.save()
            UserAction.create(
                action_type='edit_threshold',
                comment=form.cleaned_data['comment'],
                request=request,
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
        context = {'threshold': threshold, 'form': form}
        return scirius_render(request, 'rules/edit_threshold.html', context)


@permission_required('rules.ruleset_policy_edit', raise_exception=True)
def delete_threshold(request, threshold_id):
    threshold = get_object_or_404(Threshold, pk=threshold_id)
    ruleset = threshold.ruleset
    rule = threshold.rule

    if request.method == 'POST':  # If the form has been submitted...
        form = CommentForm(request.POST)
        if form.is_valid():
            action_type = 'delete_suppress_rule' if threshold.threshold_type == 'suppress' else 'delete_threshold'
            UserAction.create(
                action_type=action_type,
                comment=form.cleaned_data['comment'],
                request=request,
                rule=rule,
                threshold=threshold,
                ruleset=ruleset
            )
            threshold.delete()
        return redirect(ruleset)
    else:
        context = {'object': threshold, 'delfn': 'delete_threshold', 'form': CommentForm()}
        return scirius_render(request, 'rules/delete.html', context)


def history(request):
    actions_type = UserAction.get_allowed_actions_type(request)
    history = UserAction.objects.filter(action_type__in=actions_type)
    history |= UserAction.objects.filter(user=request.user)
    history = history.order_by('-date')

    # useractions = HistoryTable(history)
    # tables.RequestConfig(request).configure(useractions)

    res = []
    for item in history[:50]:
        res.append({
            'description': item.generate_description(request.user),
            'comment': item.comment,
            'title': item.get_title(),
            'date': item.date,
            'icons': item.get_icons(),
            'client_ip': item.client_ip
        })

    context = {'history': res}
    return scirius_render(request, 'rules/history.html', context)


@permission_required('rules.ruleset_policy_view', raise_exception=True)
def policies(request):
    context = {}
    if request.method == 'POST':
        if 'import' in request.POST:
            form = PoliciesForm(request.POST, request.FILES, request=request)

            if not form.is_valid():
                context['error'] = 'No policies file'
                return scirius_render(request, 'rules/policies.html', context)

            try:
                PoliciesForm._import(request.FILES['file'], 'delete' in request.POST)
            except json.JSONDecodeError:
                context['error'] = 'JSON is wrongly formatted'
            else:
                context['success'] = 'Successfully imported'
        elif 'export' in request.POST:
            file_tar_io = PoliciesForm._export()
            response = HttpResponse(file_tar_io.getvalue(), content_type='application/gzip')
            response['Content-Disposition'] = 'attachment; filename="policies-filtersets-%s.tgz"' % str(date.today())
            return response

    return scirius_render(request, 'rules/policies.html', context)


@csp(DEFAULT_SRC=["'self'"], SCRIPT_SRC=["'unsafe-eval'"], STYLE_SRC=["'self'", "'unsafe-inline'"])
@permission_required('rules.events_view', raise_exception=True)
def hunt(request):
    context = {'current_user_url': reverse('current_user')}
    return scirius_render(request, 'rules/hunt.html', context)
