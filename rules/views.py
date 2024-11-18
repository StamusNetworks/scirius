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
import tarfile
from datetime import date

from dateutil.relativedelta import relativedelta
from django.shortcuts import get_object_or_404, redirect
from django.utils import timezone
from django.http import HttpResponse, HttpResponseServerError, JsonResponse
from django.db import IntegrityError
from django.db.models.functions import Greatest
from django.conf import settings
from django.core.exceptions import ValidationError, PermissionDenied
from django.contrib import messages
from django.contrib.auth.decorators import permission_required
from elasticsearch.exceptions import ConnectionError as ESConnectionError
import django_tables2 as tables

from scirius.utils import (
    get_middleware_module, scirius_render,
    scirius_listing, RequestsWrapper,
    convert_to_local, is_ajax
)

from rules.es_data import ESData
from rules.models import RuleAtVersion, Ruleset, Source, SourceUpdate, Category, Rule, SuppressedRuleAtVersion, dependencies_check, get_system_settings
from rules.models import Threshold, Transformation, RulesetTransformation, UserAction
from rules.tables import UpdateRuleTable, DeletedRuleTable, ThresholdTable, SourceUpdateTable

from rules.es_graphs import ESError, ESRulesStats, ESFieldStatsAsTable, ESSidByHosts, ESIndices, ESDeleteAlertsBySid
from rules.es_graphs import get_es_major_version

from suricata.tasks import tasks_permission_required, check_task_perms

from .tables import RuleTable, CategoryTable, RulesetTable, CategoryRulesetTable, RuleHostTable, ESIndexessTable
from .tables import RuleThresholdTable, RuleSuppressTable, RulesetThresholdTable, RulesetSuppressTable
from .tables import EditCategoryTable, EditRuleTable, EditSourceTable
from .forms import RuleCommentForm, RuleTransformForm, CategoryTransformForm, RulesetSuppressForm, CommentForm
from .forms import AddRuleThresholdForm, AddRuleSuppressForm, AddSourceForm, AddPublicSourceForm, SourceForm
from .forms import (
    RulesetForm, RulesetEditForm, RulesetCopyForm,
    SystemSettingsForm, KibanaDataForm, EditThresholdForm,
    PoliciesForm
)
from .suripyg import SuriHTMLFormat

MIDDLEWARE = __import__(settings.RULESET_MIDDLEWARE)


# Create your views here.
def index(request):
    ruleset_list = Ruleset.objects.all().order_by('-created_date')[:5]
    source_list = Source.objects.all().order_by('-created_date')[:5]
    context = {'ruleset_list': ruleset_list,
               'source_list': source_list}
    try:
        context['probes'] = ['"' + x + '"' for x in MIDDLEWARE.models.get_probe_hostnames()]
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
        rules = Rule.objects.filter(ruleatversion__content__icontains=search).distinct()
        if rules.count() > 0:
            length += rules.count()
            rules = RuleTable(rules)
            tables.RequestConfig(request).configure(rules)
        else:
            rules = None
        categories_ = Category.objects.filter(name__icontains=search)
        if categories_.count() > 0:
            length += categories_.count()
            categories_ = CategoryTable(categories_)
            tables.RequestConfig(request).configure(categories_)
        else:
            rules_width += 4
            categories_ = None
        rulesets = Ruleset.objects.filter(name__icontains=search)
        if rulesets.count() > 0:
            length += rulesets.count()
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
    return scirius_render(
        request,
        'rules/sources.html',
        {'sources': Source.get_sources()}
    )


@permission_required('rules.ruleset_policy_view', raise_exception=True)
def source(request, source_id, error=None, update=False, activate=False, rulesets=None):
    source = get_object_or_404(Source, pk=source_id)

    context = {
        'source': source,
        'update': update,
        'activate': activate,
        'rulesets': rulesets,
        'rules_count': source.category_set.values('rule').count()
    }

    cats = CategoryTable(Category.objects.filter(source=source).order_by('name'))
    tables.RequestConfig(request).configure(cats)
    context.update({'categories': cats})

    if error:
        context['error'] = error

    if hasattr(MIDDLEWARE.common, 'update_source'):
        context['middleware_has_update'] = True

    return scirius_render(request, 'rules/source.html', context)


@permission_required('rules.ruleset_policy_view', raise_exception=True)
def categories(request):
    assocfn = {
        'Category': {
            'table': CategoryTable,
            'manage_links': {},
            'action_links': {}
        }
    }

    return scirius_listing(request, Category, assocfn)


@permission_required('rules.ruleset_policy_view', raise_exception=True)
def category(request, cat_id):
    cat = get_object_or_404(Category, pk=cat_id)
    rules = Rule.objects.filter(category=cat)

    context = {
        'object_path': [cat.source],
        'category': cat,
        'rules': [],
    }

    for version in MIDDLEWARE.common.rules_version():
        real_version = Rule.get_last_real_version(version, **{'category__pk': cat.pk})

        rulesets_status = []
        rule_struct = {
            'version': version,
            'active': None,
            'commented': None,
            'rulesets': [],
            'version_exists': True
        }

        context['rules'].append(rule_struct)

        # active rules (at version=real_version)
        rules_table = RuleTable(rules.filter(
            ruleatversion__state=True,
            ruleatversion__version=real_version).order_by('sid')
        )
        tables.RequestConfig(request).configure(rules_table)
        rule_struct['active'] = rules_table

        # Commented rules (at version)
        commented_rules_table = RuleTable(rules.filter(
            ruleatversion__state=False,
            ruleatversion__version=real_version).order_by('sid')
        )
        tables.RequestConfig(request).configure(commented_rules_table)
        rule_struct['commented_rules'] = commented_rules_table

        for ruleset in Ruleset.objects.all():
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
        rule_struct['rulesets'] = rulesets_status

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
    context = get_middleware_module('common').sn_loggers()

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
                if is_ajax(request):
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
        template = MIDDLEWARE.common.get_es_template()
        return scirius_render(request, template, context)


def extract_rule_references(rule):
    references = []
    for ref in re.findall(r"reference: *(\w+), *(\S+);", rule.ruleatversion_set.first().content):
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
def rule(request, rule_id):
    rule = get_object_or_404(Rule, pk=rule_id)

    if is_ajax(request):
        filters = {}
        if rule.ruleatversion_set.count() > 1:
            hosts = request.GET.get('hosts', None)
            filters = {'version': get_middleware_module('common').rule_version(hosts)}

        rule_at_v = rule.ruleatversion_set.filter(**filters).first()
        content = rule_at_v.content
        highlight_content = SuriHTMLFormat(rule_at_v.content)

        data = {'msg': rule.msg, 'sid': rule.sid, 'content': content,
                'highlight_content': highlight_content}
        return JsonResponse(data)

    context = build_rule_context(request, rule)
    return scirius_render(request, 'rules/rule.html', context)


def build_rule_context(request, rule):
    same_real_version = set()
    context = {
        'reference': extract_rule_references(rule),
        'comment_form': RuleCommentForm(),
        'rule': rule,
        'show_rule_toggle': rule.are_ravs_synched() and rule.are_ravs_all_commented(),
        'history': rule.get_actions(request.user),
        'object_path': [rule.category.source, rule.category],
        'rules_at_version': [],
        'rulesets': [],
    }

    # version is version of the probe, can be u40
    # real_version of the rule which can be u39
    # u40 are be shown but actions are done on u39 rule at versions
    versions = MIDDLEWARE.common.rules_version()
    added = []
    for version in versions:
        real_version = Rule.get_last_real_version(version, **{'pk': rule.pk})

        if real_version not in added:
            added.append(real_version)
        else:
            same_real_version.add(real_version if real_version in versions else versions[0])
            same_real_version.add(version)

        for rav in rule.ruleatversion_set.filter(version=real_version):
            rav_struct = {
                'instance': rav,
                'version': version,
                'content': SuriHTMLFormat(rav.content),
                'rule_transformations': False,
                'rulesets': [],
                'thresholds': None,
                'suppress': None,
                'version_exists': True
            }
            context['rules_at_version'].append(rav_struct)

            for ruleset in Ruleset.objects.all():
                status = 'Disabled'

                is_suppressed = SuppressedRuleAtVersion.objects.filter(
                    ruleset=ruleset,
                    rule_at_version__in=rule.ruleatversion_set.all()
                ).count() > 0

                if rav.state and rule.category in ruleset.categories.all() and not is_suppressed:
                    status = 'Enabled'

                threshold = False
                if Threshold.objects.filter(rule=rule, ruleset=ruleset, threshold_type='threshold'):
                    threshold = True

                suppress = False
                if Threshold.objects.filter(rule=rule, ruleset=ruleset, threshold_type='suppress'):
                    suppress = True

                content = SuriHTMLFormat(rav.generate_content(ruleset))
                ruleset_info = {'name': ruleset.name, 'pk': ruleset.pk, 'status': status,
                                'threshold': threshold, 'suppress': suppress,
                                'a_drop': False, 'a_filestore': False, 'a_bypass': False,
                                'l_auto': False, 'l_yes': False,
                                't_auto': False, 't_src': False, 't_dst': False,
                                'content': content}

                # get rule transaformations
                for TYPE in (Transformation.ACTION, Transformation.LATERAL, Transformation.TARGET):
                    trans = rule.get_transformation(ruleset, TYPE, override=True)
                    prefix = 'a_'

                    if TYPE == Transformation.LATERAL:
                        prefix = 'l_'
                    if TYPE == Transformation.TARGET:
                        prefix = 't_'

                    if trans is not None:
                        ruleset_info[prefix + trans.value] = True
                        rav_struct['rule_transformations'] = True

                rav_struct['rulesets'].append(ruleset_info)

            thresholds = Threshold.objects.filter(rule=rule, threshold_type='threshold')
            if thresholds:
                thresholds = RuleThresholdTable(thresholds)
                tables.RequestConfig(request).configure(thresholds)
                rav_struct['thresholds'] = thresholds
            suppress = Threshold.objects.filter(rule=rule, threshold_type='suppress')
            if suppress:
                suppress = RuleSuppressTable(suppress)
                tables.RequestConfig(request).configure(suppress)
                rav_struct['suppress'] = suppress
            try:
                context['probes'] = ['"' + x + '"' for x in MIDDLEWARE.models.get_probe_hostnames()]
            except:
                pass

    # order versions asc
    same_real_version = list(same_real_version)
    same_real_version.sort()
    context['same_real_version'] = [f'v{version}' if version != 0 else '<v39' for version in same_real_version]
    context['kibana_version'] = get_es_major_version()
    return context


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
                    elif form_trans == NONE:
                        UserAction.create(
                            action_type='transform_rule',
                            comment=form.cleaned_data['comment'],
                            request=request,
                            transformation='%s: %s' % (TYPE.value.title(), trans.value.title()) if trans else 'removed target',
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
                if rulesets.count() == rulesets_res[key][value] or \
                        (None in rulesets_res[key] and rulesets.count() == rulesets_res[key][value] + rulesets_res[key][None]):
                    if value:
                        initial[key.value] = current_trans[key].value

        # Case 3: differents transformations are applied on n rulesets
        for key, dict_val in rulesets_res.items():
            for val in dict_val.keys():

                if rulesets.count() == rulesets_res[key][val] or \
                        (None in rulesets_res[key] and rulesets.count() == rulesets_res[key][val] + rulesets_res[key][None]):
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

    context = {
        'rulesets': rulesets,
        'rule': rule_object,
        'form': form,
        'category_transforms': category_transforms,
        'ruleset_transforms': ruleset_transforms,
        'rule_state': True in rule_object.ruleatversion_set.values_list('state', flat=True),
        'object_path': [rule_object]
    }
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
                    RULESET_DEFAULT = None
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
                if rulesets.count() == rulesets_res[key][value] or \
                        (None in rulesets_res[key] and rulesets.count() == rulesets_res[key][value] + rulesets_res[key][None]):
                    if value:
                        initial[key.value] = current_trans[key].value

        # Case 3: differents transformations are applied on n rulesets
        for key, dict_val in rulesets_res.items():
            for val in dict_val.keys():

                if rulesets.count() == rulesets_res[key][val] or \
                        (None in rulesets_res[key] and rulesets.count() == rulesets_res[key][val] + rulesets_res[key][None]):
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
                suppressed_rules = SuppressedRuleAtVersion.objects.filter(ruleset=ruleset).values_list('rule_at_version__rule__pk', flat=True).distinct()

                if rule_object.pk not in suppressed_rules and operation == 'disable':
                    rule_object.disable(ruleset, request=request, comment=form.cleaned_data['comment'])
                elif rule_object.pk in suppressed_rules and operation == 'enable':
                    rule_object.enable(ruleset, request=request, comment=form.cleaned_data['comment'])
                ruleset.save()
            return redirect(rule_object)
    else:
        form = RulesetSuppressForm()

    context = {'rule': rule_object, 'form': form, 'object_path': [rule_object]}
    rulesets = Ruleset.objects.all()
    for ruleset in rulesets:
        deps_ravs = rule_object.get_dependant_rules_at_version(ruleset)

        # keep only one version to show as dependencies
        parents_sid = []
        for rav in deps_ravs.copy():
            sid = rav.rule.sid
            if sid in parents_sid:
                deps_ravs.remove(rav)
            parents_sid.append(sid)

        ruleset.deps_ravs = deps_ravs
    context['rulesets'] = rulesets
    context['operation'] = operation
    context['rule_state'] = True in rule_object.ruleatversion_set.values_list('state', flat=True)
    return scirius_render(request, 'rules/disable_rule.html', context)


@permission_required('rules.ruleset_policy_edit', raise_exception=True)
def disable_rule(request, rule_id):
    return switch_rule(request, rule_id)


@permission_required('rules.ruleset_policy_edit', raise_exception=True)
def enable_rule(request, rule_id):
    return switch_rule(request, rule_id, operation='enable')


@permission_required('rules.ruleset_policy_view', raise_exception=True)
def test_rule(request, rule_id, ruleset_id):
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
            if hasattr(MIDDLEWARE.common, 'es_delete_alerts_by_sid'):
                MIDDLEWARE.common.es_delete_alerts_by_sid(rule_id, request=request)
            else:
                errors = ESDeleteAlertsBySid(request).get(rule_id)
                if errors:
                    context = {'object': rule_object, 'error': ', '. join(errors)}
                    try:
                        context['probes'] = ['"' + x + '"' for x in MIDDLEWARE.models.get_probe_hostnames()]
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
            context['probes'] = ['"' + x + '"' for x in MIDDLEWARE.models.get_probe_hostnames()]
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
def rule_toggle_availability(request, rule_id):
    rule = get_object_or_404(Rule, pk=rule_id)

    if not request.method == 'POST':
        context = {'object': rule, 'error': 'Invalid action'}
        return scirius_render(request, 'rules/rule.html', context)

    for rav in rule.ruleatversion_set.all():
        rav.toggle_availability()

    UserAction.create(
        action_type='toggle_availability',
        request=request,
        rule=rule,
        # version='all'
    )

    return redirect(rule)


@permission_required('rules.ruleset_policy_edit', raise_exception=True)
def rav_toggle_availability(request, rav_id):
    rav = get_object_or_404(RuleAtVersion, pk=rav_id)
    rule = Rule.objects.get(pk=rav.rule.sid)

    if not request.method == 'POST':
        context = {'object': rule, 'error': 'Invalid action'}
        return scirius_render(request, 'rules/rule.html', context)

    rav.toggle_availability()

    UserAction.create(
        action_type='toggle_availability',
        request=request,
        rule=rule,
        # version=rav.version
    )

    return redirect(rule)


@permission_required('rules.ruleset_policy_edit', raise_exception=True)
def threshold_rule(request, rule_id):
    rule_object = get_object_or_404(Rule, sid=rule_id)

    if request.method == 'POST':  # If the form has been submitted...
        action_type = 'create_threshold'

        if request.POST['threshold_type'] == 'threshold':
            form = AddRuleThresholdForm(request.POST)
        else:
            form = AddRuleSuppressForm(request.POST)
            action_type = 'suppress_rule'

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
    if request.method != 'POST':  # If the form has been submitted...
        if is_ajax(request):
            data = {
                'status': False,
                'errors': 'Invalid method for page'
            }
            return JsonResponse(data)
        return source(request, source_id, error="Invalid method for page")

    get_object_or_404(Source, pk=source_id)
    MIDDLEWARE.models.CeleryTask.spawn(
        'SourceUpdateParentTask',
        source_pk=source_id,
        user=request.user
    )

    if is_ajax(request):
        data = {'status': True}
        return JsonResponse(data)

    return redirect('status')


@permission_required('rules.source_edit', raise_exception=True)
def activate_source(request, source_id, ruleset_id):

    if request.method != 'POST':  # If the form has been submitted...
        if is_ajax(request):
            data = {}
            data['status'] = False
            data['errors'] = "Invalid method for page"
            return JsonResponse(data)
        return source(request, source_id, error="Invalid method for page")

    src = get_object_or_404(Source, pk=source_id)
    ruleset = get_object_or_404(Ruleset, pk=ruleset_id)

    ruleset.sources.add(src)
    for cat in Category.objects.filter(source=src):
        cat.enable(ruleset, request=request)

    ruleset.needs_test()
    ruleset.save()
    return JsonResponse(True, safe=False)


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
    if supdate.count() == 0:
        return scirius_render(request, 'rules/source.html', {'source': source, 'error': "No changelog"})
    changelogs = SourceUpdateTable(supdate)
    tables.RequestConfig(request).configure(changelogs)
    diff = supdate[0].diff()
    build_source_diff(request, diff)
    return scirius_render(request, 'rules/source.html', {'source': source, 'diff': diff, 'changelogs': changelogs, 'src_update': supdate[0]})


@permission_required('rules.source_edit', raise_exception=True)
def add_source(request):
    if request.method == 'POST':
        form = AddSourceForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                src: Source = form.save()
                src.add_self_in_rulesets(form.cleaned_data.get('rulesets', []), request)
                form.update(request)
            except IntegrityError as error:
                return scirius_render(request, 'rules/add_source.html', {'form': form, 'error': error})

            UserAction.create(
                action_type='create_source',
                comment=form.cleaned_data['comment'],
                request=request,
                source=src
            )

            return redirect('status')
        else:
            return scirius_render(
                request,
                'rules/add_source.html',
                {'form': form, 'error': 'form is not valid'}
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

    if is_ajax(request):
        return JsonResponse(public_sources['sources'])

    if request.method == 'POST':
        form = AddPublicSourceForm(request.POST, public_sources=public_sources)
        if form.is_valid():
            try:
                src: Source = form.save()
                src.add_self_in_rulesets(form.cleaned_data.get('rulesets', []), request)
                form.update(request)
            except IntegrityError as error:
                return scirius_render(request, 'rules/add_public_source.html', {'form': form, 'error': error})

            UserAction.create(
                action_type='create_source',
                comment=form.cleaned_data['comment'],
                request=request,
                source=src,
                ruleset='No Ruleset'
            )

            return redirect('status')
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
        if form.is_valid():
            try:
                form.save()
                form.update(request, prev_uri)
            except Exception as e:
                if isinstance(e, ValidationError):
                    e = e.message
                return scirius_render(
                    request,
                    'rules/add_source.html',
                    {'form': form, 'source': source, 'error': e}
                )
            else:
                UserAction.create(
                    action_type='edit_source',
                    comment=form.cleaned_data['comment'],
                    request=request,
                    source=source
                )

                return redirect(source)
    else:
        form = SourceForm(instance=source)

    return scirius_render(
        request,
        'rules/add_source.html',
        {'form': form, 'source': source, 'object_path': [source]}
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
    context = {}

    if mode == 'struct':
        categories_list = {}
        sources = ruleset.sources.order_by('name')
        for source in sources:
            cats = CategoryTable(ruleset.categories.filter(source=source).order_by('name'))
            tables.RequestConfig(request, paginate={"per_page": 15}).configure(cats)
            categories_list[source.name] = cats

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

        A_REJECT = Transformation.A_REJECT
        A_DROP = Transformation.A_DROP
        A_FILESTORE = Transformation.A_FILESTORE

        for trans in (A_REJECT, A_DROP, A_FILESTORE):
            # Rules transformation
            trans_rules = ruleset.rules_transformation.filter(ruletransformation__value=trans.value).all()
            if trans_rules.count():
                trans_rules_t = RuleTable(trans_rules.order_by('sid'))
                tables.RequestConfig(request).configure(trans_rules_t)

                ctx_lb = '%s_rules' % trans.value
                context[ctx_lb] = trans_rules_t

            # Categories Transformation
            trans_categories = ruleset.categories_transformation.filter(
                categorytransformation__value=trans.value
            ).all()

            if trans_categories.count():
                trans_categories_t = CategoryTable(trans_categories.order_by('name'))
                tables.RequestConfig(request).configure(trans_categories_t)
                context['%s_categories' % trans.value] = trans_categories_t

        suppr_rules_pk = SuppressedRuleAtVersion.objects.filter(
            ruleset=ruleset
        ).values_list('rule_at_version__rule__pk', flat=True).distinct()

        suppr_rules = Rule.objects.filter(pk__in=suppr_rules_pk)
        suppr_rules_t = RuleTable(suppr_rules.order_by('sid'))
        tables.RequestConfig(request).configure(suppr_rules_t)
        context['disabled_rules'] = suppr_rules_t

    elif mode == 'display':
        vers_ravs = get_middleware_module('common').rules_at_version_from_ruleset(ruleset)

        all_rules = {}
        for version, ravs in vers_ravs.items():
            rules = Rule.objects.filter(ruleatversion__pk__in=ravs.values_list('pk', flat=True))
            rules_table = RuleTable(rules)
            tables.RequestConfig(request).configure(rules_table)
            all_rules[version] = rules_table
        context = {'ruleset': ruleset, 'all_rules': all_rules, 'mode': mode}
        if error:
            context['error'] = error

    rule_versions = MIDDLEWARE.common.rules_version()
    context['single_rule_version'] = True if len(rule_versions) == 1 else False
    return scirius_render(request, 'rules/ruleset.html', context)


@permission_required('rules.ruleset_policy_view', raise_exception=True)
def ruleset_export(request, ruleset_id):
    ruleset = get_object_or_404(Ruleset, pk=ruleset_id)
    rule_versions = MIDDLEWARE.common.rules_version()

    if request.method == 'POST':
        version = request.POST['version']
        file_tar_io = MIDDLEWARE.common.ruleset_export(ruleset, int(version))
        response = HttpResponse(file_tar_io.getvalue(), content_type='application/gzip')
        filename = f'rules-v{version}-{date.today()}.tgz' if version != '0' else f'rules-{date.today()}.tgz'
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response

    if rule_versions == [0] and ruleset.sources.filter(datatype__in=MIDDLEWARE.common.custom_source_datatype()).count() == 0:
        file_tar_io = MIDDLEWARE.common.ruleset_export(ruleset, 0)
        response = HttpResponse(file_tar_io.getvalue(), content_type='application/gzip')
        response['Content-Disposition'] = 'attachment; filename="rules-%s.tgz"' % str(date.today())
        return response

    return scirius_render(request, 'rules/ruleset_export.html', {'ruleset': ruleset, 'versions': rule_versions})


@permission_required('rules.source_edit', raise_exception=True)
def add_ruleset(request):
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
        if is_ajax(request):
            data = {}
            data['status'] = False
            data['errors'] = "Invalid method for page"
            return JsonResponse(data)
        return ruleset(rset, ruleset_id, error="Invalid method for page")

    MIDDLEWARE.common.update_ruleset(request, rset)

    if is_ajax(request):
        data = {'status': True}
        return JsonResponse(data)
    return redirect('status')


@permission_required('rules.source_view', raise_exception=True)
def changelog_ruleset(request, ruleset_id):
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
                if SuppressedRuleAtVersion.objects.filter(
                    ruleset=ruleset,
                    rule_at_version__in=rule_object.ruleatversion_set.all()
                ).count() > 0:

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
            for src_pk in source_selection:
                source = get_object_or_404(Source, pk=src_pk)
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
        for source in sources:
            src_cats = Category.objects.filter(source=source)
            for pcats in src_cats:
                if pcats in ruleset_cats:
                    cats_selection.append(str(pcats.id))

            cats = EditCategoryTable(src_cats)
            tables.RequestConfig(request, paginate=False).configure(cats)
            categories_list[source.name] = cats

        rules_pk = SuppressedRuleAtVersion.objects.filter(
            ruleset=ruleset
        ).values('rule_at_version__rule__pk').distinct()
        rules = EditRuleTable(Rule.objects.filter(pk__in=rules_pk))
        tables.RequestConfig(request, paginate=False).configure(rules)

        context = {
            'ruleset': ruleset,
            'categories_list': categories_list,
            'sources': sources,
            'rules': rules,
            'cats_selection': ", ".join(cats_selection),
            'extra_links': get_middleware_module('common').get_edit_ruleset_links(ruleset_id),
            'object_path': [ruleset]
        }

        if 'mode' in request.GET:
            context['mode'] = mode
            context['form'] = CommentForm()
            if context['mode'] == 'sources':
                all_sources = Source.objects.all()

                sources_selection = []
                for source_ in sources:
                    sources_selection.append(source_.pk)

                sources_list = EditSourceTable(all_sources)
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

            if trans_action.count() > 0:
                initial['action'] = trans_action[0].value

            trans_lateral = RulesetTransformation.objects.filter(
                key=Transformation.LATERAL.value,
                ruleset_transformation=ruleset
            )

            if trans_lateral.count() > 0:
                initial['lateral'] = trans_lateral[0].value

            trans_target = RulesetTransformation.objects.filter(
                key=Transformation.TARGET.value,
                ruleset_transformation=ruleset
            )

            if trans_target.count() > 0:
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
            rules = EditRuleTable(
                Rule.objects.filter(ruleatversion__content__icontains=request.POST['search']).distinct()
            )
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
    context = {
        'ruleset': ruleset,
        'rules': rules,
        'extra_links': get_middleware_module('common').get_edit_ruleset_links(ruleset_id),
        'form': CommentForm()
    }
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
        policies = ruleset.get_single_policies()
        context = {'object': ruleset, 'delfn': 'delete_ruleset', 'policies': policies, 'form': CommentForm()}
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
        'use_loggers': MIDDLEWARE.common.use_stamuslogger(),
        'ruleset_curator_available': False,
    }

    if request.method == 'POST':
        form_id = request.POST.get('form_id', None)
        comment = {'comment': request.POST.get('comment', None)}

        if form_id == 'main':
            main_form = SystemSettingsForm(request.POST, instance=gsettings, request=request)
            context['main_form'] = main_form
            if main_form.is_valid():
                main_form.save()
                context['success'] = "All changes saved."
            else:
                context['error'] = "Invalid form."

        elif form_id == 'es':
            es_data = ESData()
            try:
                _, errors = es_data.es_clear()
                if errors:
                    context['warning'] = ', '.join(errors)
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
        elif form_id == 'curator':
            if not request.user.has_perms(['rules.ruleset_policy_edit', 'rules.configuration_edit']):
                raise PermissionDenied("You do not have the permission to edit the ruleset policy or to create a recurrent task")
            result = get_middleware_module('common').extra_ruleset_curator_form(request)
            if result:  # form.errors
                context['error'] = f"Invalid curator form: {result}"
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
    if request.user.has_perms(['rules.ruleset_policy_edit', 'rules.configuration_edit']):
        context['ruleset_curator_available'] = get_middleware_module('common').is_ruleset_curator_available()
        context['rulesets'] = get_middleware_module('common').get_rulesets_with_extra(sizes=True, curators=True)
        context['monthly'] = True  # enable monthly choice on recurrent tasks
        date_time = timezone.now() + relativedelta(days=1, hour=3, minute=0, second=0, microsecond=0)
        context['schedule_param'] = date_time.strftime('%Y/%m/%d %H:%M')
        context['recurrence_param'] = 'daily'
    return scirius_render(request, 'rules/system_settings.html', context)


def info(request):
    data = {'status': 'green'}
    if request.GET.__contains__('query'):
        info = MIDDLEWARE.common.Info()
        query = request.GET.get('query', 'status')
        if query == 'status':
            data = info.status()
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

    context = {
        'rule_at_versions': [],
        'threshold': threshold
    }
    for version in MIDDLEWARE.common.rules_version():
        real_version = Rule.get_last_real_version(version, **{'pk': threshold.rule.pk})
        for rav in threshold.rule.ruleatversion_set.filter(version=real_version):
            rav_struct = {
                'version': version,
                'content': SuriHTMLFormat(rav.content)
            }
            context['rule_at_versions'].append(rav_struct)

    threshold.highlight_content = SuriHTMLFormat(str(threshold))
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
            except tarfile.ReadError as e:
                context['error'] = str(e).title()
            else:
                context['success'] = 'Successfully imported'
        elif 'export' in request.POST:
            file_tar_io = PoliciesForm._export()
            response = HttpResponse(file_tar_io.getvalue(), content_type='application/gzip')
            response['Content-Disposition'] = 'attachment; filename="policies-filtersets-%s.tgz"' % str(date.today())
            return response

    return scirius_render(request, 'rules/policies.html', context)


def status(request):
    qlength = 20
    if request.GET.__contains__('length'):
        qlength = int(request.GET.get('length', 20))

    if is_ajax(request) or request.GET.__contains__('ajax'):
        tasks_list = MIDDLEWARE.models.CeleryTask.get_user_tasks(request)

        if not request.GET.__contains__('show_hidden'):
            tasks_list = tasks_list.filter(hidden=False)

        tasks_list = tasks_list.annotate(date=Greatest('finished', 'eta', 'created')).order_by('-date')[:qlength]
        task_in_progress = False

        tasks = []
        for task in tasks_list:
            if task.get_state() in ('STARTED', 'RETRY', 'RECEIVED'):
                task_in_progress = True
            can_edit = request.user.has_perm(task.get_task().REQUIRED_GROUPS['WRITE'])
            tasks.insert(0, task.display(full=False, can_edit=can_edit))

        if task_in_progress:
            data = {'msg': 'Task(s) in progress', 'tasks': tasks}
        else:
            data = {'msg': 'No Task in progress', 'tasks': tasks}

        return JsonResponse(data)

    context = {}
    return scirius_render(request, 'rules/status.html', context)


@tasks_permission_required(MIDDLEWARE.models.RecurrentTask)
def stasks(request, reccurent_task_qs):
    assocfn = {
        'Recurrent Task': {
            'table': MIDDLEWARE.tables.RecurrentTaskTable,
            'manage_links': {},
            'action_links': {}
        }
    }

    extra_params = {}
    if MIDDLEWARE.__name__ != 'suricata':
        extra_params.update({
            'template': f'{MIDDLEWARE.__name__}/object_list.html'
        })

    return scirius_listing(
        request,
        reccurent_task_qs.exclude(task='NotebookGenerationTask'),
        assocfn,
        **extra_params
    )


@tasks_permission_required(MIDDLEWARE.models.CeleryTask)
def task(request, task_id):
    t = get_object_or_404(MIDDLEWARE.models.CeleryTask, pk=task_id)

    if request.method == 'POST':
        raise PermissionDenied()

    context = {'task': t.display()}
    return scirius_render(request, "rules/task.html", context)


@tasks_permission_required(MIDDLEWARE.models.CeleryTask)
def revoke_task(request, task_id):
    t = get_object_or_404(MIDDLEWARE.models.CeleryTask, pk=task_id)

    if request.method == 'GET':
        raise PermissionDenied()

    t.revoke()
    context = {
        'success': 'Revocation succeeded',
        'task': t.display()
    }

    return scirius_render(request, "rules/task.html", context)


@permission_required('rules.configuration_view', raise_exception=True)
@tasks_permission_required(MIDDLEWARE.models.RecurrentTask)
def scheduledtask(request, task_id):
    stask = get_object_or_404(MIDDLEWARE.models.RecurrentTask, pk=task_id)
    task = stask.get_task()
    details = task.display_details()
    task_options = task.task_options
    task_options.pop('overrided_params', None)

    can_edit = check_task_perms(
        request,
        MIDDLEWARE.models.RecurrentTask,
        stask.pk, raise_exception=False
    ).exists() and request.user.has_perm('rules.configuration_edit')

    context = {
        'scheduledtask': stask,
        'task': details,
        'can_edit': can_edit,
        'task_options': task_options
    }
    return scirius_render(request, "rules/scheduledtask.html", context)


@permission_required('rules.configuration_edit', raise_exception=True)
@tasks_permission_required(MIDDLEWARE.models.RecurrentTask)
def delete_scheduledtask(request, task_id):
    stask = get_object_or_404(MIDDLEWARE.models.RecurrentTask, pk=task_id)
    if request.method == 'POST':
        stask.delete()
        return redirect('view_stasks')
    else:
        context = {
            'scheduledtask': stask,
            'task': stask.get_task().display(),
            'mode': 'deletion'
        }
        return scirius_render(request, 'rules/scheduledtask.html', context)


@permission_required('rules.configuration_edit', raise_exception=True)
@tasks_permission_required(MIDDLEWARE.models.RecurrentTask)
def edit_scheduledtask(request, task_id):
    stask = get_object_or_404(MIDDLEWARE.models.RecurrentTask, pk=task_id)
    form = MIDDLEWARE.forms.EditRecurrentTaskForm(
        request.POST if request.method == 'POST' else None,
        instance=stask,
        request=request
    )
    task_options = stask.get_task().task_options
    task_options.pop('overrided_params', None)

    context = {
        'scheduledtask': stask,
        'task': stask.get_task().display(),
        'mode': 'edition',
        'form': form,
        'task_options': task_options,
        'recurrence': True,
        'schedule': True,
        'recurrence_param': stask.recurrence,
        'schedule_param': convert_to_local(stask.scheduled, request.user).strftime('%Y/%m/%d %H:%M'),
        'monthly': True
    }

    if request.method == 'POST':
        if form.is_valid():
            form.save()
            return redirect(MIDDLEWARE.common.stask_redirection(stask.task))
        else:
            context.update({
                'error': f'Invalid form: {form.errors.as_text()}',
                'recurrence_param': form.cleaned_data['recurrence'],
                'schedule_param': convert_to_local(form.cleaned_data['scheduled'], request.user).strftime('%Y/%m/%d %H:%M'),
            })
    return scirius_render(request, 'rules/scheduledtask.html', context)
