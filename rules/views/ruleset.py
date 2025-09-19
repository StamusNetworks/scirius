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

from datetime import date

import django_tables2 as tables
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import permission_required
from django.core.exceptions import PermissionDenied
from django.db import IntegrityError
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect
from ipware.ip import HttpRequest

from rules.forms.common import CommentForm
from rules.forms.ruleset import RulesetCopyForm, RulesetEditForm, RulesetForm
from rules.models import (
    Category,
    Rule,
    Ruleset,
    RulesetTransformation,
    Source,
    SuppressedRuleAtVersion,
    Threshold,
    Transformation,
    UserAction,
    dependencies_check,
)
from rules.tables import (
    CategoryTable,
    EditCategoryTable,
    EditRuleTable,
    EditSourceTable,
    RulesetSuppressTable,
    RulesetThresholdTable,
    RuleTable,
)
from scirius.utils import (
    get_middleware_module,
    is_ajax,
    scirius_render,
)

MIDDLEWARE = __import__(settings.RULESET_MIDDLEWARE)


@permission_required("rules.source_view", raise_exception=True)
def rulesets(request: HttpRequest):
    rulesets = Ruleset.objects.all().order_by("name")
    for ruleset in rulesets:
        ruleset.number_of_rules()
    context = {"rulesets": rulesets}
    return scirius_render(request, "rules/rulesets.html", context)


@permission_required("rules.ruleset_policy_view", raise_exception=True)
def ruleset(request: HttpRequest, ruleset_id: int, mode: str = "struct", error=None):
    ruleset = get_object_or_404(Ruleset, pk=ruleset_id)
    context = {}

    if mode == "struct":
        categories_list = {}
        sources = ruleset.sources.order_by("name")
        for source in sources:
            cats = CategoryTable(ruleset.categories.filter(source=source).order_by("name"))
            tables.RequestConfig(request, paginate={"per_page": 15}).configure(cats)
            categories_list[source.name] = cats

        context = {"ruleset": ruleset, "categories_list": categories_list, "sources": sources, "mode": mode}

        # Threshold
        thresholds = Threshold.objects.filter(ruleset=ruleset, threshold_type="threshold")
        if thresholds:
            thresholds = RulesetThresholdTable(thresholds)
            tables.RequestConfig(request).configure(thresholds)
            context["thresholds"] = thresholds

        suppress = Threshold.objects.filter(ruleset=ruleset, threshold_type="suppress")
        if suppress:
            suppress = RulesetSuppressTable(suppress)
            tables.RequestConfig(request).configure(suppress)
            context["suppress"] = suppress

        # Error
        if error:
            context["error"] = error

        A_REJECT = Transformation.A_REJECT
        A_DROP = Transformation.A_DROP
        A_FILESTORE = Transformation.A_FILESTORE

        for trans in (A_REJECT, A_DROP, A_FILESTORE):
            # Rules transformation
            trans_rules = ruleset.rules_transformation.filter(ruletransformation__value=trans.value).all()
            if trans_rules.count():
                trans_rules_t = RuleTable(trans_rules.order_by("sid"))
                tables.RequestConfig(request).configure(trans_rules_t)

                ctx_lb = "%s_rules" % trans.value
                context[ctx_lb] = trans_rules_t

            # Categories Transformation
            trans_categories = ruleset.categories_transformation.filter(categorytransformation__value=trans.value).all()

            if trans_categories.count():
                trans_categories_t = CategoryTable(trans_categories.order_by("name"))
                tables.RequestConfig(request).configure(trans_categories_t)
                context["%s_categories" % trans.value] = trans_categories_t

        suppr_rules_pk = (
            SuppressedRuleAtVersion.objects.filter(ruleset=ruleset)
            .values_list("rule_at_version__rule__pk", flat=True)
            .distinct()
        )

        suppr_rules = Rule.objects.filter(pk__in=suppr_rules_pk)
        suppr_rules_t = RuleTable(suppr_rules.order_by("sid"))
        tables.RequestConfig(request).configure(suppr_rules_t)
        context["disabled_rules"] = suppr_rules_t

    elif mode == "display":
        vers_ravs = get_middleware_module("common").rules_at_version_from_ruleset(ruleset)

        all_rules = {}
        for version, ravs in vers_ravs.items():
            rules = Rule.objects.filter(ruleatversion__pk__in=ravs.values_list("pk", flat=True))
            rules_table = RuleTable(rules)
            tables.RequestConfig(request).configure(rules_table)
            all_rules[version] = rules_table
        context = {"ruleset": ruleset, "all_rules": all_rules, "mode": mode}
        if error:
            context["error"] = error

    rule_versions = MIDDLEWARE.common.rules_version()
    context["single_rule_version"] = len(rule_versions) == 1
    return scirius_render(request, "rules/ruleset.html", context)


@permission_required("rules.ruleset_policy_view", raise_exception=True)
def ruleset_export(request: HttpRequest, ruleset_id: int):
    ruleset = get_object_or_404(Ruleset, pk=ruleset_id)
    rule_versions = MIDDLEWARE.common.rules_version()

    if request.method == "POST":
        version = request.POST["version"]
        file_tar_io = MIDDLEWARE.common.ruleset_export(ruleset, int(version))
        response = HttpResponse(file_tar_io.getvalue(), content_type="application/gzip")
        filename = f"rules-v{version}-{date.today()}.tgz" if version != "0" else f"rules-{date.today()}.tgz"
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response

    if (
        rule_versions == [0] and ruleset.sources.filter(datatype__in=MIDDLEWARE.common.custom_source_datatype()).count() == 0
    ):
        file_tar_io = MIDDLEWARE.common.ruleset_export(ruleset, 0)
        response = HttpResponse(file_tar_io.getvalue(), content_type="application/gzip")
        response["Content-Disposition"] = f'attachment; filename="rules-{date.today()!s}.tgz"'
        return response

    return scirius_render(request, "rules/ruleset_export.html", {"ruleset": ruleset, "versions": rule_versions})


@permission_required("rules.source_edit", raise_exception=True)
def add_ruleset(request: HttpRequest):
    extra_form = get_middleware_module("common").extra_ruleset_form(request)

    context = {}
    if extra_form:
        context = extra_form.get_context()
        context["extra_form"] = extra_form

    if request.method == "POST":  # If the form has been submitted...
        form = RulesetForm(request.POST)  # A form bound to the POST data
        context["form"] = form

        if form.is_valid() and (extra_form is None or extra_form.is_valid()):  # All validation rules pass
            ruleset = extra_form.cleaned_data["ruleset"] if extra_form else None
            try:
                if ruleset is None:
                    ruleset = Ruleset.create_ruleset(
                        name=form.cleaned_data["name"],
                        sources=form.cleaned_data["sources"].values_list("pk", flat=True),
                        activate_categories=form.cleaned_data["activate_categories"],
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

                context.update({"form": form, "error": error})
                return scirius_render(request, "rules/add_ruleset.html", context)

            UserAction.create(
                action_type="create_ruleset", comment=form.cleaned_data["comment"], request=request, ruleset=ruleset
            )

            msg = """All changes are saved. Don't forget to update the ruleset to apply the changes.
                     After the ruleset Update the changes would be updated on the probe(s) upon the next Ruleset Push"""

            messages.success(request, msg)
            return redirect(ruleset)
        else:
            if form.errors:
                context["error"] = repr(form.errors)

        if extra_form.data.get("ruleset", False):
            Ruleset.objects.filter(pk=extra_form.data["ruleset"]).delete()
    else:
        initial = {
            "action": Transformation.A_NONE.value,
            "lateral": Transformation.L_AUTO.value,
            "target": Transformation.T_AUTO.value,
        }
        form = RulesetForm(initial=initial)  # An unbound form
        context["form"] = form

        missing = dependencies_check(Ruleset)
        if missing:
            context["missing"] = missing

    return scirius_render(request, "rules/add_ruleset.html", context)


@permission_required("rules.ruleset_update_push", raise_exception=True)
def update_ruleset(request: HttpRequest, ruleset_id: int):
    rset = get_object_or_404(Ruleset, pk=ruleset_id)
    if request.method != "POST":  # If the form has been submitted...
        if is_ajax(request):
            data = {}
            data["status"] = False
            data["errors"] = "Invalid method for page"
            return JsonResponse(data)
        return ruleset(rset, ruleset_id, error="Invalid method for page")

    MIDDLEWARE.common.update_ruleset(request, rset)

    if is_ajax(request):
        data = {"status": True}
        return JsonResponse(data)
    return redirect("status")


@permission_required("rules.source_view", raise_exception=True)
def changelog_ruleset(request: HttpRequest, ruleset_id: int):
    ruleset = get_object_or_404(Ruleset, pk=ruleset_id)
    return get_middleware_module("common").changelog_ruleset(request, ruleset)


def edit_ruleset(request: HttpRequest, ruleset_id: int):
    user = request.user
    if not user.has_perm("rules.ruleset_policy_edit") and not user.has_perm("rules.source_edit"):
        raise PermissionDenied()

    ruleset = get_object_or_404(Ruleset, pk=ruleset_id)

    if request.method == "POST":  # If the form has been submitted...
        # check if this is a categories edit
        # ID is unique so we can just look by indice and add
        form = CommentForm(request.POST)
        if not form.is_valid():
            return redirect(ruleset)

        if "category" in request.POST:
            if not user.has_perm("rules.ruleset_policy_edit"):
                raise PermissionDenied()

            category_selection = [int(x) for x in request.POST.getlist("category_selection")]
            # clean ruleset
            for cat in ruleset.categories.all():
                if cat.pk not in category_selection:
                    cat.disable(ruleset, request=request, comment=form.cleaned_data["comment"])

            # add updated entries
            for cat in category_selection:
                category = get_object_or_404(Category, pk=cat)
                if category not in ruleset.categories.all():
                    category.enable(ruleset, request=request, comment=form.cleaned_data["comment"])

        elif "rules" in request.POST:
            if not user.has_perm("rules.ruleset_policy_edit"):
                raise PermissionDenied()

            for rule in request.POST.getlist("rule_selection"):
                rule_object = get_object_or_404(Rule, pk=rule)
                if (
                    SuppressedRuleAtVersion.objects.filter(
                        ruleset=ruleset, rule_at_version__in=rule_object.ruleatversion_set.all()
                    ).count() > 0
                ):
                    rule_object.enable(ruleset, request=request, comment=form.cleaned_data["comment"])

        elif "sources" in request.POST:
            if not user.has_perm("rules.source_edit"):
                raise PermissionDenied()

            source_selection = [int(x) for x in request.POST.getlist("source_selection")]
            # clean ruleset
            for source_ in ruleset.sources.all():
                if source_.pk not in source_selection:
                    source_.disable(ruleset, request=request, comment=form.cleaned_data["comment"])

            # add new entries
            for src_pk in source_selection:
                source = get_object_or_404(Source, pk=src_pk)
                if source not in ruleset.sources.all():
                    source.enable(ruleset, request=request, comment=form.cleaned_data["comment"])
        else:
            form = RulesetEditForm(request.POST, instance=ruleset, request=request)

            if form.is_valid():
                UserAction.create(
                    action_type="edit_ruleset", comment=form.cleaned_data["comment"], request=request, ruleset=ruleset
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
                    request, "rules/edit_ruleset.html", {"ruleset": ruleset, "error": "Invalid form.", "form": form}
                )

        msg = """All changes are saved. Don't forget to update the ruleset to apply the changes.
                 After the ruleset Update the changes would be updated on the probe(s) upon the next Ruleset Push"""

        messages.success(request, msg)

        return redirect(ruleset)
    else:
        mode = request.GET.get("mode", None)

        if mode == "sources":
            if not user.has_perm("rules.source_edit"):
                raise PermissionDenied()
        elif mode in ("categories", "rules") and not user.has_perm("rules.ruleset_policy_edit"):
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

        rules_pk = (
            SuppressedRuleAtVersion.objects.filter(ruleset=ruleset).values("rule_at_version__rule__pk").distinct()
        )
        rules = EditRuleTable(Rule.objects.filter(pk__in=rules_pk))
        tables.RequestConfig(request, paginate=False).configure(rules)

        context = {
            "ruleset": ruleset,
            "categories_list": categories_list,
            "sources": sources,
            "rules": rules,
            "cats_selection": ", ".join(cats_selection),
            "extra_links": get_middleware_module("common").get_edit_ruleset_links(ruleset_id),
            "object_path": [ruleset],
        }

        if "mode" in request.GET:
            context["mode"] = mode
            context["form"] = CommentForm()
            if context["mode"] == "sources":
                all_sources = Source.objects.all()

                sources_selection = [source_.pk for source_ in sources]

                sources_list = EditSourceTable(all_sources)
                tables.RequestConfig(request, paginate=False).configure(sources_list)
                context["sources_list"] = sources_list
                context["sources_selection"] = sources_selection
        else:
            initial = {
                "action": Transformation.A_NONE.value,
                "lateral": Transformation.L_NO.value,
                "target": Transformation.T_NONE.value,
            }
            trans_action = RulesetTransformation.objects.filter(
                key=Transformation.ACTION.value, ruleset_transformation=ruleset
            )

            if trans_action.count() > 0:
                initial["action"] = trans_action[0].value

            trans_lateral = RulesetTransformation.objects.filter(
                key=Transformation.LATERAL.value, ruleset_transformation=ruleset
            )

            if trans_lateral.count() > 0:
                initial["lateral"] = trans_lateral[0].value

            trans_target = RulesetTransformation.objects.filter(
                key=Transformation.TARGET.value, ruleset_transformation=ruleset
            )

            if trans_target.count() > 0:
                initial["target"] = trans_target[0].value

            # trans_action = CategoryTransformation.objects.filter(key=Transformation.ACTION.value, ruleset=ruleset)
            # if len(trans_action) > 0:
            #     initial['action'] = trans_action[0].value

            # trans_lateral = CategoryTransformation.objects.filter(key=Transformation.LATERAL.value, ruleset=ruleset)
            # if len(trans_lateral) > 0:
            #     initial['lateral'] = trans_lateral[0].value

            # trans_target = CategoryTransformation.objects.filter(key=Transformation.TARGET.value, ruleset=ruleset)
            # if len(trans_action) > 0:
            #     initial['target'] = trans_target[0].value

            context["form"] = RulesetEditForm(instance=ruleset, initial=initial, request=request)
        return scirius_render(request, "rules/edit_ruleset.html", context)


@permission_required("rules.ruleset_policy_edit", raise_exception=True)
def ruleset_add_supprule(request: HttpRequest, ruleset_id: int):
    ruleset = get_object_or_404(Ruleset, pk=ruleset_id)
    if request.method == "POST":  # If the form has been submitted...
        if "search" in request.POST:
            # FIXME Protection on SQL injection ?
            rules = EditRuleTable(
                Rule.objects.filter(ruleatversion__content__icontains=request.POST["search"]).distinct()
            )
            tables.RequestConfig(request).configure(rules)
            context = {"ruleset": ruleset, "rules": rules, "form": CommentForm()}
            return scirius_render(request, "rules/search_rule.html", context)
        elif "rule_selection" in request.POST:
            form = CommentForm(request.POST)
            if not form.is_valid():
                return redirect(ruleset)
            for rule in request.POST.getlist("rule_selection"):
                rule_object = get_object_or_404(Rule, pk=rule)
                rule_object.disable(ruleset, request=request, comment=form.cleaned_data["comment"])
            ruleset.save()
        return redirect(ruleset)

    rules = EditRuleTable(Rule.objects.all())
    tables.RequestConfig(request).configure(rules)
    context = {
        "ruleset": ruleset,
        "rules": rules,
        "extra_links": get_middleware_module("common").get_edit_ruleset_links(ruleset_id),
        "form": CommentForm(),
    }
    return scirius_render(request, "rules/search_rule.html", context)


@permission_required("rules.source_edit", raise_exception=True)
def delete_ruleset(request: HttpRequest, ruleset_id: int):
    ruleset = get_object_or_404(Ruleset, pk=ruleset_id)

    if request.method == "POST":  # If the form has been submitted...
        form = CommentForm(request.POST)
        if form.is_valid():
            UserAction.create(
                action_type="delete_ruleset", comment=form.cleaned_data["comment"], request=request, ruleset=ruleset
            )
            ruleset.delete()
        return redirect("/rules/ruleset/")
    policies = ruleset.get_single_policies()
    context = {"object": ruleset, "delfn": "delete_ruleset", "policies": policies, "form": CommentForm()}
    return scirius_render(request, "rules/delete.html", context)


@permission_required("rules.source_edit", raise_exception=True)
def copy_ruleset(request: HttpRequest, ruleset_id: int):
    ruleset = get_object_or_404(Ruleset, pk=ruleset_id)
    if request.method == "POST":  # If the form has been submitted...
        form = RulesetCopyForm(request.POST)  # A form bound to the POST data
        if form.is_valid():  # All validation rules pass
            copy = ruleset.copy(form.cleaned_data["name"])
            UserAction.create(
                action_type="copy_ruleset", comment=form.cleaned_data["comment"], request=request, ruleset=ruleset
            )
            return redirect(copy)
    else:
        form = RulesetCopyForm()
    context = {"object": ruleset, "form": form}
    return scirius_render(request, "rules/copy_ruleset.html", context)
