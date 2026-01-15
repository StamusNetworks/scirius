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

import os
import re

import django_tables2 as tables
import yaml
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import permission_required
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.http import HttpRequest, JsonResponse
from django.shortcuts import get_object_or_404, redirect

from rules.forms.common import CommentForm
from rules.forms.source import (
    AddPublicSourceForm,
    AddSourceForm,
    SourceForm,
    get_ioc_meta_formset,
)
from rules.models.model import Category, IoCMeta, Source, SourceUpdate, Ruleset, UserAction
from rules.tables import (
    CategoryTable,
    DeletedRuleTable,
    SourceUpdateTable,
    UpdateRuleTable,
)
from scirius.utils import (
    RequestsWrapper,
    is_ajax,
    scirius_render,
)

MIDDLEWARE = __import__(settings.RULESET_MIDDLEWARE)


@permission_required("rules.source_view", raise_exception=True)
def sources(request: HttpRequest):
    return scirius_render(request, "rules/sources.html", {"sources": Source.get_sources()})


@permission_required("rules.ruleset_policy_view", raise_exception=True)
def source(
    request: HttpRequest, source_id: int, error=None, update: bool = False, activate: bool = False, rulesets=None
):
    source = get_object_or_404(Source, pk=source_id)

    context = {
        "source": source,
        "update": update,
        "activate": activate,
        "rulesets": rulesets,
        "rules_count": source.category_set.values("rule").count(),
    }

    cats = CategoryTable(Category.objects.filter(source=source).order_by("name"))
    tables.RequestConfig(request).configure(cats)
    context.update({"categories": cats})

    if error:
        context["error"] = error

    if hasattr(MIDDLEWARE.common, "update_source"):
        context["middleware_has_update"] = True

    return scirius_render(request, "rules/source.html", context)


@permission_required("rules.source_view", raise_exception=True)
def changelog_source(request: HttpRequest, source_id: int):
    source = get_object_or_404(Source, pk=source_id)

    supdate = SourceUpdate.objects.filter(source=source).order_by("-created_date")
    # get last for now
    if supdate.count() == 0:
        return scirius_render(request, "rules/source.html", {"source": source, "error": "No changelog"})
    changelogs = SourceUpdateTable(supdate)
    tables.RequestConfig(request).configure(changelogs)
    diff = supdate[0].diff()
    build_source_diff(request, diff)
    return scirius_render(
        request,
        "rules/source.html",
        {"source": source, "diff": diff, "changelogs": changelogs, "src_update": supdate[0]},
    )


@permission_required("rules.source_edit", raise_exception=True)
def add_source(request: HttpRequest):
    IoCMetaFormset = get_ioc_meta_formset()
    if request.method == "POST":
        form = AddSourceForm(request.POST, request.FILES)
        ioc_meta_formset = IoCMetaFormset(request.POST)

        if form.is_valid() and ioc_meta_formset.is_valid():
            try:
                src: Source = form.save()
                ioc_metadata_instances = ioc_meta_formset.save()

                for ioc_meta in ioc_metadata_instances:
                    src.ioc_meta.add(ioc_meta)

                src.add_self_in_rulesets(form.cleaned_data.get("rulesets", []), request)
                form.update(request)
            except IntegrityError as error:
                return scirius_render(
                    request,
                    "rules/add_source.html",
                    {
                        "form": form,
                        "ioc_meta_formset": ioc_meta_formset,
                        "rules": Source.ioc_rules(highlight=True),
                        "error": error,
                    },
                )

            UserAction.create(
                action_type="create_source", comment=form.cleaned_data["comment"], request=request, source=src
            )

            return redirect("status")
        errors = [error for error in ioc_meta_formset.errors if error]
        context = {
            "form": form,
            "ioc_meta_formset": ioc_meta_formset,
            "rules": Source.ioc_rules(highlight=True),
        }
        # if we don't have IoC error, we have the error twice (below the field and on the top red bar)
        if errors:
            context["error"] = f"form is not valid: {errors}"
        return scirius_render(request, "rules/add_source.html", context)
    form = AddSourceForm()  # An unbound form
    ioc_meta_formset = IoCMetaFormset(queryset=IoCMeta.objects.none())

    return scirius_render(
        request,
        "rules/add_source.html",
        {"form": form, "ioc_meta_formset": ioc_meta_formset, "rules": Source.ioc_rules(highlight=True)},
    )


def fetch_public_sources():
    resp = RequestsWrapper().get(url=settings.DEFAULT_SOURCE_INDEX_URL)

    # store as sources.yaml
    if not os.path.isdir(settings.GIT_SOURCES_BASE_DIRECTORY):
        os.makedirs(settings.GIT_SOURCES_BASE_DIRECTORY)

    sources_yaml = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, "sources.yaml")
    with open(sources_yaml, "wb") as sfile:
        sfile.write(resp.content)


@permission_required("rules.source_edit", raise_exception=True)
def update_public_sources(request: HttpRequest):
    fetch_public_sources()
    return redirect("add_public_source")


def get_public_sources(force_fetch: bool = True):
    sources_yaml = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, "sources.yaml")
    if not os.path.exists(sources_yaml) or force_fetch is True:
        try:
            fetch_public_sources()
        except Exception as e:
            raise Exception(e)

    public_sources = None
    with open(sources_yaml, "r", encoding="utf-8") as stream:
        buf = stream.read()
        # replace dash by underscode in keys
        yaml_data = re.sub(r"(\s+\w+)-(\w+):", r"\1_\2:", buf)
        # FIXME error handling
        public_sources = yaml.load(yaml_data, Loader=yaml.CSafeLoader)  # noqa: DUO109

    if public_sources["version"] != 1:
        raise Exception("Unsupported version of sources definition")

    # get list of already defined public sources
    defined_pub_source = Source.objects.exclude(public_source__isnull=True)
    added_sources = [x.public_source for x in defined_pub_source]

    for source_ in public_sources["sources"]:
        if "support_url" in public_sources["sources"][source_]:
            public_sources["sources"][source_]["support_url_cleaned"] = public_sources["sources"][source_][
                "support_url"
            ].split(" ")[0]
        if "subscribe_url" in public_sources["sources"][source_]:
            public_sources["sources"][source_]["subscribe_url_cleaned"] = public_sources["sources"][source_][
                "subscribe_url"
            ].split(" ")[0]
        if public_sources["sources"][source_]["url"].endswith(".rules"):
            public_sources["sources"][source_]["datatype"] = "sig"
        elif public_sources["sources"][source_]["url"].endswith("z"):
            public_sources["sources"][source_]["datatype"] = "sigs"
        else:
            public_sources["sources"][source_]["datatype"] = "other"
        if source_ in added_sources:
            public_sources["sources"][source_]["added"] = True
        else:
            public_sources["sources"][source_]["added"] = False

    return public_sources


@permission_required("rules.source_edit", raise_exception=True)
def add_public_source(request: HttpRequest):
    try:
        public_sources = get_public_sources()
    except Exception as e:
        return scirius_render(request, "rules/add_public_source.html", {"error": e})

    if is_ajax(request):
        return JsonResponse(public_sources["sources"])

    if request.method == "POST":
        form = AddPublicSourceForm(request.POST, public_sources=public_sources)
        if form.is_valid():
            try:
                src: Source = form.save()
                src.add_self_in_rulesets(form.cleaned_data.get("rulesets", []), request)
                form.update(request)
            except IntegrityError as error:
                return scirius_render(request, "rules/add_public_source.html", {"form": form, "error": error})

            UserAction.create(
                action_type="create_source",
                comment=form.cleaned_data["comment"],
                request=request,
                source=src,
                ruleset="No Ruleset",
            )

            return redirect("status")
        return scirius_render(request, "rules/add_public_source.html", {"form": form, "error": "form is not valid"})

    rulesets = Ruleset.objects.all()
    return scirius_render(
        request, "rules/add_public_source.html", {"sources": public_sources["sources"], "rulesets": rulesets}
    )


@permission_required("rules.source_edit", raise_exception=True)
def delete_ioc_metadata(request: HttpRequest, ioc_meta_id: int):
    ioc_meta = get_object_or_404(IoCMeta, pk=ioc_meta_id)
    if request.method != "POST" or not is_ajax(request):
        data = {"errors": "Method not allowed.", "status": False}
        return JsonResponse(data)

    ioc_meta.delete()
    return JsonResponse({"status": True})


@permission_required("rules.source_edit", raise_exception=True)
def edit_source(request: HttpRequest, source_id: int):
    source = get_object_or_404(Source, pk=source_id)
    IoCMetaFormset = get_ioc_meta_formset()

    if request.method == "POST":  # If the form has been submitted...
        prev_uri = source.uri
        prev_method = source.method
        form = SourceForm(request.POST, request.FILES, instance=source)
        ioc_meta_formset = IoCMetaFormset(request.POST)

        if form.is_valid() and ioc_meta_formset.is_valid():
            try:
                form.save()
                ioc_metadata_instances = ioc_meta_formset.save()

                # add new ioc_meta to source
                # keep old ioc_meta
                for ioc_meta in ioc_metadata_instances:
                    source.ioc_meta.add(ioc_meta)

                need_update = form.update(request, prev_uri, prev_method)
            except Exception as e:
                if isinstance(e, ValidationError):
                    e = e.message
                return scirius_render(
                    request,
                    "rules/add_source.html",
                    {
                        "form": form,
                        "source": source,
                        "ioc_meta_formset": ioc_meta_formset,
                        "rules": Source.ioc_rules(highlight=True, src_instance=source),
                        "error": e,
                    },
                )
            else:
                UserAction.create(
                    action_type="edit_source", comment=form.cleaned_data["comment"], request=request, source=source
                )

                if need_update:
                    return redirect("status")

                messages.success(request, "All changes are saved. Don't forget to update/push ruleset.")
                return scirius_render(
                    request,
                    "rules/add_source.html",
                    {
                        "form": form,
                        "source": source,
                        "ioc_meta_formset": IoCMetaFormset(queryset=IoCMeta.objects.filter(ioc_source=source)),
                        "rules": Source.ioc_rules(highlight=True, src_instance=source),
                    },
                )

        else:
            errors = [error for error in ioc_meta_formset.errors if error]
            context = {
                "form": form,
                "ioc_meta_formset": ioc_meta_formset,
                "rules": Source.ioc_rules(highlight=True),
            }
            # if we don't have IoC error, we have the error twice (below the field and on the top red bar)
            if errors:
                context["error"] = f"form is not valid: {errors}"
    else:
        form = SourceForm(instance=source)
        ioc_meta_formset = IoCMetaFormset(queryset=IoCMeta.objects.filter(ioc_source=source))

    return scirius_render(
        request,
        "rules/add_source.html",
        {
            "form": form,
            "source": source,
            "ioc_meta_formset": ioc_meta_formset,
            "rules": Source.ioc_rules(highlight=True, src_instance=source),
            "object_path": [source],
        },
    )


@permission_required("rules.source_edit", raise_exception=True)
def delete_source(request: HttpRequest, source_id: int):
    source = get_object_or_404(Source, pk=source_id)

    if request.method == "POST":  # If the form has been submitted...
        form = CommentForm(request.POST)
        if form.is_valid():
            UserAction.create(
                action_type="delete_source", comment=form.cleaned_data["comment"], request=request, source=source
            )
            source.delete()
        return redirect("/rules/source/")
    context = {"object": source, "delfn": "delete_source", "form": CommentForm()}
    return scirius_render(request, "rules/delete.html", context)


@permission_required("rules.source_edit", raise_exception=True)
def sourceupdate(request: HttpRequest, update_id: int):
    sourceupdate = get_object_or_404(SourceUpdate, pk=update_id)
    source = sourceupdate.source
    diff = sourceupdate.diff()
    build_source_diff(request, diff)
    return scirius_render(request, "rules/source.html", {"source": source, "diff": diff, "src_update": sourceupdate})


@permission_required("rules.ruleset_update_push", raise_exception=True)
def update_source(request, source_id):
    if request.method != "POST":  # If the form has been submitted...
        if is_ajax(request):
            data = {"status": False, "errors": "Invalid method for page"}
            return JsonResponse(data)
        return source(request, source_id, error="Invalid method for page")

    get_object_or_404(Source, pk=source_id)
    MIDDLEWARE.task_models.CeleryTask.spawn("SourceUpdateParentTask", source_pk=source_id, user=request.user)

    if is_ajax(request):
        data = {"status": True}
        return JsonResponse(data)

    return redirect("status")


@permission_required("rules.source_edit", raise_exception=True)
def activate_source(request: HttpRequest, source_id: int, ruleset_id: int):
    if request.method != "POST":  # If the form has been submitted...
        if is_ajax(request):
            data = {}
            data["status"] = False
            data["errors"] = "Invalid method for page"
            return JsonResponse(data)
        return source(request, source_id, error="Invalid method for page")

    src = get_object_or_404(Source, pk=source_id)
    ruleset = get_object_or_404(Ruleset, pk=ruleset_id)

    ruleset.sources.add(src)
    for cat in Category.objects.filter(source=src):
        cat.enable(ruleset, request=request)

    return JsonResponse(True, safe=False)


def build_source_diff(request: HttpRequest, diff):
    for field in ["added", "deleted", "updated"]:
        if field == "deleted":
            diff[field] = DeletedRuleTable(diff[field])
        else:
            diff[field] = UpdateRuleTable(diff[field])
        tables.RequestConfig(request).configure(diff[field])
