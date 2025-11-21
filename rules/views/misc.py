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
import os
from typing import Any

import django_tables2 as tables
from dateutil.relativedelta import relativedelta
from django.conf import settings
from django.contrib.auth.decorators import permission_required
from django.core.exceptions import PermissionDenied
from django.http import HttpRequest, HttpResponse, HttpResponseServerError, JsonResponse
from django.utils import timezone
from elasticsearch.exceptions import ConnectionError as ESConnectionError

from rules.es_data import ESData
from rules.es_graphs import (
    ESError,
    ESFieldStatsAsTable,
    ESIndices,
    ESRulesStats,
    ESSidByHosts,
)
from rules.forms.common import CommentForm
from rules.forms.misc import KibanaDataForm, SystemSettingsForm
from rules.models.model import Category, Ruleset, Source, Rule, UserAction
from rules.models.misc import get_system_settings
from rules.tables import (
    CategoryTable,
    ESIndexessTable,
    RuleHostTable,
    RulesetTable,
    RuleTable,
)
from scirius.utils import (
    get_middleware_module,
    is_ajax,
    scirius_render,
)

MIDDLEWARE = __import__(settings.RULESET_MIDDLEWARE)


# Create your views here.
def index(request: HttpRequest):
    ruleset_list = Ruleset.objects.all().order_by("-created_date")[:5]
    source_list = Source.objects.all().order_by("-created_date")[:5]
    context = {"ruleset_list": ruleset_list, "source_list": source_list}
    with contextlib.suppress(builtins.BaseException):
        context["probes"] = ['"' + x + '"' for x in MIDDLEWARE.models.get_probe_hostnames()]
    return scirius_render(request, "rules/index.html", context)


@permission_required("rules.ruleset_policy_view", raise_exception=True)
def search(request: HttpRequest):
    context = {}
    length = 0
    rules_width = 4
    search = None
    if request.method == "POST":
        if "search" in request.POST:
            search = request.POST["search"]
            request.GET = request.GET.copy()
            request.GET.update({"search": search})
    elif request.method == "GET" and "search" in request.GET:
        search = request.GET["search"]
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
        "rules": rules,
        "rules_width": rules_width,
        "categories": categories_,
        "rulesets": rulesets,
        "motif": search,
        "length": length,
    }
    return scirius_render(request, "rules/search.html", context)


def history(request: HttpRequest):
    actions_type = UserAction.get_allowed_actions_type(request)
    history = UserAction.objects.filter(action_type__in=actions_type)
    history |= UserAction.objects.filter(user=request.user)
    history = history.order_by("-date")

    # useractions = HistoryTable(history)
    # tables.RequestConfig(request).configure(useractions)

    res: list[dict[str, Any]] = [
        {
            "description": item.generate_description(request.user),
            "comment": item.comment,
            "title": item.get_title(),
            "date": item.date,
            "icons": item.get_icons(),
            "client_ip": item.client_ip,
        }
        for item in history[:50]
    ]

    context = {"history": res}
    return scirius_render(request, "rules/history.html", context)


def info(request: HttpRequest):
    data = {"status": "green"}
    if request.GET.__contains__("query"):
        info = MIDDLEWARE.common.Info()
        query = request.GET.get("query", "status")
        if query == "status":
            data = info.status()
        elif query == "disk":
            data = info.disk()
        elif query == "memory":
            data = info.memory()
        elif query == "used_memory":
            data = info.used_memory()
        elif query == "cpu":
            data = info.cpu()
    return JsonResponse(data, safe=False)


@permission_required("rules.configuration_view", raise_exception=True)
def system_settings(request):
    gsettings = get_system_settings()
    main_form = SystemSettingsForm(instance=gsettings, request=request)
    kibana_form = KibanaDataForm()

    context = {
        "form_id": "main",
        "main_form": main_form,
        "kibana_form": kibana_form,
        "use_loggers": MIDDLEWARE.common.use_stamuslogger(),
        "ruleset_curator_available": False,
    }

    if request.method == "POST":
        form_id = request.POST.get("form_id", None)
        comment = {"comment": request.POST.get("comment", None)}

        if form_id == "main":
            main_form = SystemSettingsForm(request.POST, instance=gsettings, request=request)
            context["main_form"] = main_form
            if main_form.is_valid():
                main_form.save()
                context["success"] = "All changes saved."
            else:
                context["error"] = "Invalid form."

        elif form_id == "es":
            es_data = ESData()
            try:
                _, errors = es_data.es_clear()
                if errors:
                    context["warning"] = ", ".join(errors)
                context["success"] = "Done"
            except ESConnectionError:
                context["error"] = "Could not connect to Elasticsearch"
            except Exception as e:
                context["error"] = "Clearing failed: %s" % e

        elif form_id == "kibana":
            es_data = ESData()
            if "export" in request.POST:
                tar_name, tar_file = es_data.kibana_export()

                with open(tar_file, "rb") as f:
                    content = f.read()

                os.unlink(tar_file)
                response = HttpResponse(content, content_type="application/x-bzip2")
                response["Content-Disposition"] = 'attachment; filename="%s"' % tar_name
                return response
            if "import" in request.POST:
                form = KibanaDataForm(request.POST, request.FILES)
                if form.is_valid() and "file" in request.FILES:
                    try:
                        count = es_data.kibana_import_fileobj(request.FILES["file"])
                        context["success"] = "Successfully imported %i objects" % count
                    except Exception as e:
                        context["error"] = "Import failed: %s" % e
                else:
                    context["error"] = "Please provide a dashboard archive"
            elif "clear" in request.POST:
                try:
                    es_data.kibana_clear()
                    context["success"] = "Done"
                except Exception as e:
                    context["error"] = "Clearing failed: %s" % e
            elif "reset" in request.POST:
                try:
                    es_data.kibana_reset()
                    context["success"] = "Done"
                except Exception as e:
                    context["error"] = "Reset failed: %s" % e
            else:
                context["error"] = "Invalid operation"
        elif form_id == "curator":
            if not request.user.has_perms(["rules.ruleset_policy_edit", "rules.configuration_edit"]):
                raise PermissionDenied(
                    "You do not have the permission to edit the ruleset policy or to create a recurrent task"
                )
            result = get_middleware_module("common").extra_ruleset_curator_form(request)
            if result:  # form.errors
                context["error"] = f"Invalid curator form: {result}"
        else:
            context["error"] = "Invalid form id."

        if form_id is not None:
            context["form_id"] = form_id

        comment_form = CommentForm(comment)
        comment_form.is_valid()
        UserAction.create(
            action_type="system_settings",
            comment=comment_form.cleaned_data["comment"],
            request=request,
        )
    context["global_settings"] = get_system_settings()
    if request.user.has_perms(["rules.ruleset_policy_edit", "rules.configuration_edit"]):
        context["ruleset_curator_available"] = get_middleware_module("common").is_ruleset_curator_available()
        context["rulesets"] = get_middleware_module("common").get_rulesets_with_extra(sizes=True, curators=True)
        context["monthly"] = True  # enable monthly choice on recurrent tasks
        date_time = timezone.now() + relativedelta(days=1, hour=3, minute=0, second=0, microsecond=0)
        context["schedule_param"] = date_time.strftime("%Y/%m/%d %H:%M")
        context["recurrence_param"] = "daily"
    return scirius_render(request, "rules/system_settings.html", context)


def elasticsearch(request: HttpRequest):
    RULE_FIELDS_MAPPING = {
        "rule_src": "src_ip",
        "rule_dest": "dest_ip",
        "rule_source": "alert.source.ip",
        "rule_target": "alert.target.ip",
        "rule_probe": settings.ELASTICSEARCH_HOSTNAME,
        "field_stats": None,
    }
    context = get_middleware_module("common").sn_loggers()

    def check_perms(query):
        PERM_CONF_VIEW = ("indices", "rule_probe", "field_stats", None)
        PERM_EVENT_VIEW = ("rule_src", "rule_dest", "rule_source", "rule_target")
        PERM_CONF_AND_EVENT_VIEW = ("rules", "rule")

        if query in PERM_EVENT_VIEW and not request.user.has_perm("rules.events_view"):
            raise PermissionDenied

        if query in PERM_CONF_VIEW and not request.user.has_perm("rules.configuration_view"):
            raise PermissionDenied

        if (
            query in PERM_CONF_AND_EVENT_VIEW and not request.user.has_perm("rules.configuration_view") and not request.user.has_perm("rules.events_view")
        ):
            raise PermissionDenied

    if request.GET.__contains__("query"):
        query = request.GET.get("query")
        check_perms(query)
        try:
            if query == "rules":
                rules = ESRulesStats(request).get()
                if rules is None:
                    return JsonResponse(rules)
                context["table"] = rules
                return scirius_render(request, "rules/table.html", context)
            if query == "rule":
                sid = request.GET.get("sid", None)
                hosts = ESSidByHosts(request).get(sid)
                context["table"] = hosts
                return scirius_render(request, "rules/table.html", context)
            if query in list(RULE_FIELDS_MAPPING.keys()):
                ajax = request.GET.get("json", None)
                if ajax:
                    raise ESError("Use REST API instead.")

                filter_ip = request.GET.get("field", "src_ip") if query == "field_stats" else RULE_FIELDS_MAPPING[query]

                sid = request.GET.get("sid", None)
                count = request.GET.get("page_size", 10)

                hosts = ESFieldStatsAsTable(request).get(
                    sid, filter_ip + "." + settings.ELASTICSEARCH_KEYWORD, RuleHostTable, count=count
                )
                context["table"] = hosts
                return scirius_render(request, "rules/table.html", context)
            if query == "indices":
                if is_ajax(request):
                    indices = ESIndexessTable(ESIndices(request).get())
                    tables.RequestConfig(request).configure(indices)
                    context["table"] = indices
                    return scirius_render(request, "rules/table.html", context)
                return scirius_render(request, "rules/elasticsearch.html", context)
            raise Exception(f"Query parameter not supported: {query}")
        except ESError as e:
            return HttpResponseServerError(str(e))
    else:
        check_perms(None)
        template = MIDDLEWARE.common.get_es_template()
        return scirius_render(request, template, context)
