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

import builtins
import contextlib
import orjson as json
import tarfile
from datetime import datetime, UTC

import django_tables2 as tables
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import permission_required
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect

from rules.es_graphs import ESDeleteAlertsBySid, get_es_major_version
from rules.forms.common import CommentForm
from rules.forms.rule import (
    AddRuleSuppressForm,
    AddRuleThresholdForm,
    EditThresholdForm,
    PoliciesForm,
    RuleCommentForm,
    RuleTransformForm,
)
from rules.forms.ruleset import RulesetSuppressForm
from rules.models.model import Ruleset, SuppressedRuleAtVersion, Threshold, Transformation
from rules.models.model import Rule, RuleAtVersion, UserAction
from rules.services.transformation import TransformationService
from rules.suripyg import SuriHTMLFormat
from rules.tables import RuleSuppressTable, RuleThresholdTable, ThresholdTable
from scirius.utils import (
    get_middleware_module,
    is_ajax,
    scirius_render,
)

MIDDLEWARE = __import__(settings.RULESET_MIDDLEWARE)


@permission_required("rules.ruleset_policy_view", raise_exception=True)
def threshold(request: HttpRequest, threshold_id: int):
    threshold = get_object_or_404(Threshold, pk=threshold_id)

    context = {"rule_at_versions": [], "threshold": threshold}
    for version in MIDDLEWARE.common.rules_version():
        real_version = Rule.get_last_real_version(version, pk=threshold.rule.pk)
        for rav in threshold.rule.ruleatversion_set.filter(version=real_version):
            rav_struct = {"version": version, "content": SuriHTMLFormat(rav.content)}
            context["rule_at_versions"].append(rav_struct)

    threshold.highlight_content = SuriHTMLFormat(str(threshold))
    return scirius_render(request, "rules/threshold.html", context)


@permission_required("rules.ruleset_policy_edit", raise_exception=True)
def edit_threshold(request: HttpRequest, threshold_id: int):
    threshold = get_object_or_404(Threshold, pk=threshold_id)
    rule = threshold.rule
    ruleset = threshold.ruleset

    if request.method == "POST":  # If the form has been submitted...
        form = EditThresholdForm(request.POST, instance=threshold)  # A form bound to the POST data
        if form.is_valid():  # All validation rules pass
            form.save()
            UserAction.create(
                action_type="edit_threshold",
                comment=form.cleaned_data["comment"],
                request=request,
                rule=rule,
                threshold=threshold,
                ruleset=ruleset,
            )
            return redirect(threshold)
        context = {"threshold": threshold, "form": form, "error": "Invalid form"}
        return scirius_render(request, "rules/edit_threshold.html", context)
    form = EditThresholdForm(instance=threshold)
    context = {"threshold": threshold, "form": form}
    return scirius_render(request, "rules/edit_threshold.html", context)


@permission_required("rules.ruleset_policy_edit", raise_exception=True)
def delete_threshold(request: HttpRequest, threshold_id: int):
    threshold = get_object_or_404(Threshold, pk=threshold_id)
    ruleset = threshold.ruleset
    rule = threshold.rule

    if request.method == "POST":  # If the form has been submitted...
        form = CommentForm(request.POST)
        if form.is_valid():
            action_type = "delete_suppress_rule" if threshold.threshold_type == "suppress" else "delete_threshold"
            UserAction.create(
                action_type=action_type,
                comment=form.cleaned_data["comment"],
                request=request,
                rule=rule,
                threshold=threshold,
                ruleset=ruleset,
            )
            threshold.delete()
        return redirect(ruleset)
    context = {"object": threshold, "delfn": "delete_threshold", "form": CommentForm()}
    return scirius_render(request, "rules/delete.html", context)


@permission_required("rules.ruleset_policy_view", raise_exception=True)
def policies(request: HttpRequest):
    context = {}
    if request.method == "POST":
        if "import" in request.POST:
            form = PoliciesForm(request.POST, request.FILES, request=request)

            if not form.is_valid():
                context["error"] = "No policies file"
                return scirius_render(request, "rules/policies.html", context)

            try:
                PoliciesForm._import(request.FILES["file"], "delete" in request.POST)
            except json.JSONDecodeError:
                context["error"] = "JSON is wrongly formatted"
            except tarfile.ReadError as e:
                context["error"] = str(e).title()
            else:
                UserAction.create(action_type="import_rule_filter", request=request)
                context["success"] = "Successfully imported"
        elif "export" in request.POST:
            file_tar_io = PoliciesForm._export()
            response = HttpResponse(file_tar_io.getvalue(), content_type="application/gzip")
            response["Content-Disposition"] = f'attachment; filename="policies-filtersets-{datetime.now(tz=UTC).date()!s}.tgz"'
            return response

    return scirius_render(request, "rules/policies.html", context)


@permission_required("rules.ruleset_policy_view", raise_exception=True)
def rule(request: HttpRequest, rule_id: int):
    rule = get_object_or_404(Rule, pk=rule_id)

    if is_ajax(request):
        filters = {}
        if rule.ruleatversion_set.count() > 1:
            hosts = request.GET.get("hosts", None)
            filters = {"version": get_middleware_module("common").rule_version(hosts)}

        rule_at_v = rule.ruleatversion_set.filter(**filters).first()
        content = rule_at_v.content
        highlight_content = SuriHTMLFormat(rule_at_v.content)

        data = {"msg": rule.msg, "sid": rule.sid, "content": content, "highlight_content": highlight_content}
        return JsonResponse(data)

    context = build_rule_context(request, rule)
    return scirius_render(request, "rules/rule.html", context)


def build_rule_context(request: HttpRequest, rule: Rule):
    same_real_version = set()
    context = {
        "reference": rule.extract_rule_references(),
        "comment_form": RuleCommentForm(),
        "rule": rule,
        "show_rule_toggle": rule.are_ravs_synched() and rule.are_ravs_all_commented(),
        "history": rule.get_actions(request.user),
        "object_path": [rule.category.source, rule.category],
        "rules_at_version": [],
        "rulesets": [],
    }

    # version is version of the probe, can be u40
    # real_version of the rule which can be u39
    # u40 are be shown but actions are done on u39 rule at versions
    versions = MIDDLEWARE.common.rules_version()
    added = []
    for version in versions:
        real_version = Rule.get_last_real_version(version, pk=rule.pk)

        if real_version not in added:
            added.append(real_version)
        else:
            same_real_version.add(real_version if real_version in versions else versions[0])
            same_real_version.add(version)

        for rav in rule.ruleatversion_set.filter(version=real_version):
            rav_struct = {
                "instance": rav,
                "version": version,
                "content": SuriHTMLFormat(rav.content),
                "rule_transformations": False,
                "rulesets": [],
                "thresholds": None,
                "suppress": None,
                "version_exists": True,
            }
            context["rules_at_version"].append(rav_struct)

            for ruleset in Ruleset.objects.all():
                status = "Disabled"

                is_suppressed = (
                    SuppressedRuleAtVersion.objects.filter(
                        ruleset=ruleset, rule_at_version__in=rule.ruleatversion_set.all()
                    ).count() > 0
                )

                if rav.state and rule.category in ruleset.categories.all() and not is_suppressed:
                    status = "Enabled"

                threshold = False
                if Threshold.objects.filter(rule=rule, ruleset=ruleset, threshold_type="threshold"):
                    threshold = True

                suppress = False
                if Threshold.objects.filter(rule=rule, ruleset=ruleset, threshold_type="suppress"):
                    suppress = True

                content = SuriHTMLFormat(rav.generate_content(ruleset))
                ruleset_info = {
                    "name": ruleset.name,
                    "pk": ruleset.pk,
                    "status": status,
                    "threshold": threshold,
                    "suppress": suppress,
                    "a_drop": False,
                    "a_filestore": False,
                    "a_bypass": False,
                    "l_auto": False,
                    "l_yes": False,
                    "t_auto": False,
                    "t_src": False,
                    "t_dst": False,
                    "content": content,
                }

                # get rule transformations
                _service = TransformationService()
                for TYPE in (Transformation.ACTION, Transformation.LATERAL, Transformation.TARGET):
                    trans = _service.get_for_rule(rule, ruleset, TYPE, override=True)
                    prefix = "a_"

                    if TYPE == Transformation.LATERAL:
                        prefix = "l_"
                    if TYPE == Transformation.TARGET:
                        prefix = "t_"

                    if trans is not None:
                        ruleset_info[prefix + trans.value] = True
                        rav_struct["rule_transformations"] = True

                rav_struct["rulesets"].append(ruleset_info)

            thresholds = Threshold.objects.filter(rule=rule, threshold_type="threshold")
            if thresholds:
                thresholds = RuleThresholdTable(thresholds)
                tables.RequestConfig(request).configure(thresholds)
                rav_struct["thresholds"] = thresholds
            suppress = Threshold.objects.filter(rule=rule, threshold_type="suppress")
            if suppress:
                suppress = RuleSuppressTable(suppress)
                tables.RequestConfig(request).configure(suppress)
                rav_struct["suppress"] = suppress
            with contextlib.suppress(builtins.BaseException):
                context["probes"] = ['"' + x + '"' for x in MIDDLEWARE.models.get_probe_hostnames()]

    # order versions asc
    same_real_version = list(same_real_version)
    same_real_version.sort()
    context["same_real_version"] = [f"v{version}" if version != 0 else "<v39" for version in same_real_version]
    context["kibana_version"] = get_es_major_version()
    return context


@permission_required("rules.ruleset_policy_edit", raise_exception=True)
def edit_rule(request: HttpRequest, rule_id: int):
    rule_object = get_object_or_404(Rule, sid=rule_id)
    _service = TransformationService()

    if request.method == "POST":  # If the form has been submitted...

        form = RuleTransformForm(request.POST, instance=rule_object)
        if form.is_valid():  # All validation rules pass
            rulesets = form.cleaned_data["rulesets"]

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

                    trans = _service.get_for_rule(rule_object, ruleset, TYPE)
                    if form_trans == CAT_DEFAULT:
                        if trans is None:
                            continue

                        cat_trans = _service.get_for_category(rule_object.category, ruleset, TYPE)
                        if cat_trans is None:
                            cat_trans = NONE

                        if trans != cat_trans:
                            UserAction.create(
                                action_type="transform_rule",
                                comment=form.cleaned_data["comment"],
                                request=request,
                                transformation="{}: {}".format(TYPE.value, CAT_DEFAULT.name.replace("_", " ").title()),
                                rule=rule_object,
                                ruleset=ruleset,
                            )

                        rule_object.remove_transformations(ruleset, TYPE)
                        continue

                    rule_object.set_transformation(ruleset, key=TYPE, value=form_trans)

                    if form_trans not in (NONE, trans):
                        UserAction.create(
                            action_type="transform_rule",
                            comment=form.cleaned_data["comment"],
                            request=request,
                            transformation=f"{TYPE.value.title()}: {form_trans.value.title()}",
                            rule=rule_object,
                            ruleset=ruleset,
                        )
                    elif form_trans == NONE:
                        UserAction.create(
                            action_type="transform_rule",
                            comment=form.cleaned_data["comment"],
                            request=request,
                            transformation=f"{TYPE.value.title()}: {trans.value.title()}"
                            if trans
                            else "removed target",
                            rule=rule_object,
                            ruleset=ruleset,
                        )

            return redirect(rule_object)
    else:
        rulesets_ids = []
        current_trans = {
            Transformation.ACTION: Transformation.A_CAT_DEFAULT,
            Transformation.LATERAL: Transformation.L_CAT_DEFAULT,
            Transformation.TARGET: Transformation.T_CAT_DEFAULT,
        }

        rulesets_res = {
            Transformation.ACTION: {},
            Transformation.LATERAL: {},
            Transformation.TARGET: {},
        }

        initial = {
            "action": current_trans[Transformation.ACTION].value,
            "lateral": current_trans[Transformation.LATERAL].value,
            "target": current_trans[Transformation.TARGET].value,
            "rulesets": rulesets_ids,
        }

        rulesets = Ruleset.objects.all()
        for ruleset in rulesets:
            trans_action = _service.get_for_rule(rule_object, ruleset, Transformation.ACTION)
            trans_lateral = _service.get_for_rule(rule_object, ruleset, Transformation.LATERAL)
            trans_target = _service.get_for_rule(rule_object, ruleset, Transformation.TARGET)
            all_trans = [
                (Transformation.ACTION, trans_action),
                (Transformation.LATERAL, trans_lateral),
                (Transformation.TARGET, trans_target),
            ]

            for key, value in all_trans:
                if value not in rulesets_res[key]:
                    rulesets_res[key][value] = 0
                rulesets_res[key][value] += 1

                if value:
                    rulesets_ids.append(ruleset.id)
                    current_trans[key] = value

                # Case 1: One transfo on all rulesets
                # Case 2: one transfo on n rulesets on x. x-n rulesets without transfo (None)
                if (
                    rulesets.count() == rulesets_res[key][value] or (
                        None in rulesets_res[key] and rulesets.count() == rulesets_res[key][value] + rulesets_res[key][None]
                    )
                ) and value:
                    initial[key.value] = current_trans[key].value

        # Case 3: differents transformations are applied on n rulesets
        for key, dict_val in rulesets_res.items():
            for val in dict_val:
                if rulesets.count() == dict_val[val] or (
                    None in dict_val and rulesets.count() == dict_val[val] + dict_val[None]
                ):
                    pass
                else:
                    initial[key.value] = "category"
                    initial.pop("rulesets", None)

        form = RuleTransformForm(initial=initial, instance=rule_object)

    category_transforms = []
    ruleset_transforms = []
    rulesets = Ruleset.objects.all()

    for ruleset in rulesets:
        trans_cats_values = []
        trans_rulesets_values = []
        for trans_key in (Transformation.ACTION, Transformation.LATERAL, Transformation.TARGET):
            trans_cat_value = _service.get_for_category(rule_object.category, ruleset, trans_key)
            trans_ruleset_value = _service.get_for_ruleset(ruleset, trans_key)

            if trans_cat_value:
                trans_cats_values.append(f"{trans_key.name.title()}: {trans_cat_value.name.title()}")

            if trans_ruleset_value:
                trans_rulesets_values.append(f"{trans_key.name.title()}: {trans_ruleset_value.name.title()}")

        if len(trans_cats_values) > 0:
            category_transforms.append({"category": rule_object.category, "trans": " | ".join(trans_cats_values)})

        if len(trans_rulesets_values) > 0:
            ruleset_transforms.append({"ruleset": ruleset, "trans": " | ".join(trans_rulesets_values)})

    context = {
        "rulesets": rulesets,
        "rule": rule_object,
        "form": form,
        "category_transforms": category_transforms,
        "ruleset_transforms": ruleset_transforms,
        "rule_state": True in rule_object.ruleatversion_set.values_list("state", flat=True),
        "object_path": [rule_object],
    }
    return scirius_render(request, "rules/edit_rule.html", context)


def switch_rule(request: HttpRequest, rule_id: int, operation: str = "disable"):
    rule_object = get_object_or_404(Rule, sid=rule_id)

    if request.method == "POST":  # If the form has been submitted...
        form = RulesetSuppressForm(request.POST)
        if form.is_valid():  # All validation rules pass
            rulesets = form.cleaned_data["rulesets"]
            for ruleset in rulesets:
                suppressed_rules = (
                    SuppressedRuleAtVersion.objects.filter(ruleset=ruleset)
                    .values_list("rule_at_version__rule__pk", flat=True)
                    .distinct()
                )

                if rule_object.pk not in suppressed_rules and operation == "disable":
                    rule_object.disable(ruleset, request=request, comment=form.cleaned_data["comment"])
                elif rule_object.pk in suppressed_rules and operation == "enable":
                    rule_object.enable(ruleset, request=request, comment=form.cleaned_data["comment"])
                ruleset.save()
            return redirect(rule_object)
    else:
        form = RulesetSuppressForm()

    context = {"rule": rule_object, "form": form, "object_path": [rule_object]}
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
    context["rulesets"] = rulesets
    context["operation"] = operation
    context["rule_state"] = True in rule_object.ruleatversion_set.values_list("state", flat=True)
    return scirius_render(request, "rules/disable_rule.html", context)


@permission_required("rules.ruleset_policy_edit", raise_exception=True)
def disable_rule(request: HttpRequest, rule_id: int):
    return switch_rule(request, rule_id)


@permission_required("rules.ruleset_policy_edit", raise_exception=True)
def enable_rule(request: HttpRequest, rule_id: int):
    return switch_rule(request, rule_id, operation="enable")


@permission_required("rules.ruleset_policy_view", raise_exception=True)
def test_rule(request: HttpRequest, rule_id: int, ruleset_id: int):
    rule_object = get_object_or_404(Rule, pk=rule_id)
    ruleset = get_object_or_404(Ruleset, pk=ruleset_id)
    ret = rule_object.test(ruleset)
    return JsonResponse(ret)


@permission_required("rules.events_edit", raise_exception=True)
def delete_alerts(request, rule_id):
    rule_object = get_object_or_404(Rule, sid=rule_id)

    if request.method == "POST":  # If the form has been submitted...
        form = CommentForm(request.POST)
        if form.is_valid():
            if hasattr(MIDDLEWARE.common, "es_delete_alerts_by_sid"):
                MIDDLEWARE.common.es_delete_alerts_by_sid(rule_id, request=request)
            else:
                errors = ESDeleteAlertsBySid(request).get(rule_id)
                if errors:
                    context = {"object": rule_object, "error": ", ".join(errors)}
                    with contextlib.suppress(builtins.BaseException):
                        context["probes"] = ['"' + x + '"' for x in MIDDLEWARE.models.get_probe_hostnames()]
                    context["comment_form"] = CommentForm()
                    return scirius_render(request, "rules/delete_alerts.html", context)

            messages.add_message(
                request, messages.INFO, "Events deletion may be in progress, graphics and stats could be not in sync."
            )
            UserAction.create(
                action_type="delete_alerts", comment=form.cleaned_data["comment"], request=request, rule=rule_object
            )
        return redirect(rule_object)
    context = {"object": rule_object}
    context["comment_form"] = CommentForm()
    with contextlib.suppress(builtins.BaseException):
        context["probes"] = ['"' + x + '"' for x in MIDDLEWARE.models.get_probe_hostnames()]
    return scirius_render(request, "rules/delete_alerts.html", context)


@permission_required("rules.ruleset_policy_edit", raise_exception=True)
def comment_rule(request, rule_id):
    rule_object = get_object_or_404(Rule, sid=rule_id)

    if request.method == "POST":  # If the form has been submitted...
        form = RuleCommentForm(request.POST)
        if form.is_valid():
            UserAction.create(
                action_type="comment_rule", comment=form.cleaned_data["comment"], request=request, rule=rule_object
            )
    return redirect(rule_object)


@permission_required("rules.ruleset_policy_edit", raise_exception=True)
def rule_toggle_availability(request, rule_id):
    rule = get_object_or_404(Rule, pk=rule_id)

    if request.method != "POST":
        context = {"object": rule, "error": "Invalid action"}
        return scirius_render(request, "rules/rule.html", context)

    for rav in rule.ruleatversion_set.all():
        rav.toggle_availability()

    UserAction.create(
        action_type="toggle_availability",
        request=request,
        rule=rule,
        # version='all'
    )

    return redirect(rule)


@permission_required("rules.ruleset_policy_edit", raise_exception=True)
def rav_toggle_availability(request: HttpRequest, rav_id: int):
    rav = get_object_or_404(RuleAtVersion, pk=rav_id)
    rule = Rule.objects.get(pk=rav.rule.sid)

    if request.method != "POST":
        context = {"object": rule, "error": "Invalid action"}
        return scirius_render(request, "rules/rule.html", context)

    rav.toggle_availability()

    UserAction.create(
        action_type="toggle_availability",
        request=request,
        rule=rule,
        # version=rav.version
    )

    return redirect(rule)


@permission_required("rules.ruleset_policy_edit", raise_exception=True)
def threshold_rule(request: HttpRequest, rule_id: int):
    rule_object = get_object_or_404(Rule, sid=rule_id)

    if request.method == "POST":  # If the form has been submitted...
        action_type = "create_threshold"

        if request.POST["threshold_type"] == "threshold":
            form = AddRuleThresholdForm(request.POST)
        else:
            form = AddRuleSuppressForm(request.POST)
            action_type = "suppress_rule"

        if form.is_valid():
            rulesets = form.cleaned_data["rulesets"]
            for ruleset in rulesets:
                threshold = form.save(commit=False)
                threshold.rule = rule_object
                threshold.ruleset = ruleset
                threshold.pk = None
                threshold.save()

                UserAction.create(
                    action_type=action_type,
                    comment=form.cleaned_data["comment"],
                    request=request,
                    rule=rule_object,
                    threshold=threshold,
                    ruleset=ruleset,
                )

            return redirect(rule_object)
        context = {"rule": rule_object, "form": form, "error": "Could not create threshold"}
        if request.POST["threshold_type"] == "suppress":
            context["type"] = "suppress"
        else:
            context["type"] = "threshold"
        return scirius_render(request, "rules/add_threshold.html", context)

    data = {"gid": 1, "count": 1, "seconds": 60, "type": "limit", "rule": rule_object, "ruleset": 1}
    if request.GET.__contains__("action"):
        data["threshold_type"] = request.GET.get("action", "suppress")
    if request.GET.__contains__("net"):
        data["net"] = request.GET.get("net", None)
    if request.GET.__contains__("dir"):
        direction = request.GET.get("dir", "both")
        if direction == "src":
            direction = "by_src"
        elif direction == "dest":
            direction = "by_dst"
        data["track_by"] = direction

    if "track_by" in data:
        containers = []
        pth = Threshold(rule=rule_object, track_by=data["track_by"], threshold_type=data["threshold_type"])

        if "net" in data:
            pth.net = data["net"]
        thresholds = Threshold.objects.filter(rule=rule_object)

        for threshold in thresholds:
            if threshold.contain(pth):
                containers.append(threshold)
                break
        if len(containers) == 0:
            containers = None
        else:
            if data["threshold_type"] == "threshold":
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

    context = {"rule": rule_object, "thresholds": thresholds, "containers": containers}
    if data["threshold_type"] == "suppress":
        context["form"] = AddRuleSuppressForm(initial=data)
        context["type"] = "suppress"
    else:
        context["form"] = AddRuleThresholdForm(initial=data)
        context["type"] = "threshold"
    return scirius_render(request, "rules/add_threshold.html", context)
