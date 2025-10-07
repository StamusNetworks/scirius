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

import django_tables2 as tables
from django.conf import settings
from django.contrib.auth.decorators import permission_required
from django.http import HttpRequest
from django.shortcuts import get_object_or_404, redirect

from rules.forms.category import CategoryTransformForm
from rules.forms.ruleset import RulesetSuppressForm
from rules.models.model import Category, Ruleset, Transformation, Rule, UserAction
from rules.tables import CategoryRulesetTable, CategoryTable, RuleTable
from scirius.utils import (
    scirius_listing,
    scirius_render,
)

MIDDLEWARE = __import__(settings.RULESET_MIDDLEWARE)


@permission_required("rules.ruleset_policy_view", raise_exception=True)
def categories(request: HttpRequest):
    assocfn = {"Category": {"table": CategoryTable, "manage_links": {}, "action_links": {}}}

    return scirius_listing(request, Category, assocfn)


@permission_required("rules.ruleset_policy_view", raise_exception=True)
def category(request: HttpRequest, cat_id: int):
    cat = get_object_or_404(Category, pk=cat_id)
    rules = Rule.objects.filter(category=cat)

    context = {
        "object_path": [cat.source],
        "category": cat,
        "rules": [],
    }

    for version in MIDDLEWARE.common.rules_version():
        real_version = Rule.get_last_real_version(version, category__pk=cat.pk)

        rulesets_status = []
        rule_struct = {"version": version, "active": None, "commented": None, "rulesets": [], "version_exists": True}

        context["rules"].append(rule_struct)

        # active rules (at version=real_version)
        rules_table = RuleTable(
            rules.filter(ruleatversion__state=True, ruleatversion__version=real_version).order_by("sid")
        )
        tables.RequestConfig(request).configure(rules_table)
        rule_struct["active"] = rules_table

        # Commented rules (at version)
        commented_rules_table = RuleTable(
            rules.filter(ruleatversion__state=False, ruleatversion__version=real_version).order_by("sid")
        )
        tables.RequestConfig(request).configure(commented_rules_table)
        rule_struct["commented_rules"] = commented_rules_table

        for ruleset in Ruleset.objects.all():
            status = "Inactive"
            if cat in ruleset.categories.all():
                status = "Active"

            transformations = {}
            for key in (Transformation.ACTION, Transformation.LATERAL, Transformation.TARGET):
                trans = cat.get_transformation(ruleset, key, override=True)
                if trans:
                    transformations[key] = f"{key.value.capitalize()}: {trans.value.capitalize()}"

            rulesets_status.append(
                {
                    "name": ruleset.name,
                    "pk": ruleset.pk,
                    "status": status,
                    "action": transformations.get(Transformation.ACTION, ""),
                    "lateral": transformations.get(Transformation.LATERAL, ""),
                    "target": transformations.get(Transformation.TARGET, ""),
                }
            )

        rulesets_status = CategoryRulesetTable(rulesets_status)
        tables.RequestConfig(request).configure(rulesets_status)
        rule_struct["rulesets"] = rulesets_status

    return scirius_render(request, "rules/category.html", context)


@permission_required("rules.ruleset_policy_view", raise_exception=True)
def transform_category(request: HttpRequest, cat_id: int):
    cat_object = get_object_or_404(Category, pk=cat_id)

    if request.method == "POST":
        form = CategoryTransformForm(request.POST, request=request)
        if form.is_valid():  # All validation rules pass
            rulesets = form.cleaned_data["rulesets"]

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
                        LOOP = (
                            Transformation.A_DROP,
                            Transformation.A_REJECT,
                            Transformation.A_FILESTORE,
                            Transformation.A_BYPASS,
                        )
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
                            action_type="transform_category",
                            comment=form.cleaned_data["comment"],
                            request=request,
                            transformation=f"{TYPE.value.title()}: {form_trans.value.title()}",
                            category=cat_object,
                            ruleset=ruleset,
                        )
                    elif trans:
                        UserAction.create(
                            action_type="transform_category",
                            comment=form.cleaned_data["comment"],
                            request=request,
                            transformation=f"{TYPE.value.title()}: {trans.value.title()}",
                            category=cat_object,
                            ruleset=ruleset,
                        )

            return redirect(cat_object)
    else:
        rulesets_ids = []
        current_trans = {
            Transformation.ACTION: Transformation.A_RULESET_DEFAULT,
            Transformation.LATERAL: Transformation.L_RULESET_DEFAULT,
            Transformation.TARGET: Transformation.T_RULESET_DEFAULT,
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
            trans_action = cat_object.get_transformation(ruleset, Transformation.ACTION)
            trans_lateral = cat_object.get_transformation(ruleset, Transformation.LATERAL)
            trans_target = cat_object.get_transformation(ruleset, Transformation.TARGET)
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
                if (rulesets.count() == rulesets_res[key][value] or (
                    None in rulesets_res[key] and rulesets.count() == rulesets_res[key][value] + rulesets_res[key][None]
                )) and value:
                    initial[key.value] = current_trans[key].value

        # Case 3: differents transformations are applied on n rulesets
        for key, dict_val in rulesets_res.items():
            for val in dict_val:
                if rulesets.count() == dict_val[val] or (
                    None in dict_val and rulesets.count() == dict_val[val] + dict_val[None]
                ):
                    pass
                else:
                    initial[key.value] = "none"
                    initial.pop("rulesets", None)

        form = CategoryTransformForm(initial=initial, request=request)

    ruleset_transforms = []
    rulesets = Ruleset.objects.all()

    for ruleset in rulesets:
        trans_values = []
        for trans_key in (Transformation.ACTION, Transformation.LATERAL, Transformation.TARGET):
            trans_value = ruleset.get_transformation(key=trans_key)
            if trans_value:
                trans_values.append(f"{trans_key.name.title()}: {trans_value.name.title()}")

        if len(trans_values) > 0:
            ruleset_transforms.append({"ruleset": ruleset, "trans": " | ".join(trans_values)})

    context = {"rulesets": rulesets, "category": cat_object, "form": form, "ruleset_transforms": ruleset_transforms}
    return scirius_render(request, "rules/edit_rule.html", context)


@permission_required("rules.ruleset_policy_edit", raise_exception=True)
def disable_category(request: HttpRequest, cat_id: int, operation: str = "suppress"):
    cat_object = get_object_or_404(Category, id=cat_id)

    if request.method == "POST":  # If the form has been submitted...
        form = RulesetSuppressForm(request.POST)
        if form.is_valid():  # All validation rules pass
            rulesets = form.cleaned_data["rulesets"]
            for ruleset in rulesets:
                if operation == "suppress":
                    cat_object.disable(ruleset, request=request, comment=form.cleaned_data["comment"])
                elif operation == "enable":
                    cat_object.enable(ruleset, request=request, comment=form.cleaned_data["comment"])
            return redirect(cat_object)
    else:
        form = RulesetSuppressForm()
    context = {"category": cat_object, "form": form, "operation": operation}
    return scirius_render(request, "rules/disable_category.html", context)


@permission_required("rules.ruleset_policy_edit", raise_exception=True)
def enable_category(request: HttpRequest, cat_id: int):
    return disable_category(request, cat_id, operation="enable")
