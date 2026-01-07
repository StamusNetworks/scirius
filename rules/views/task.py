"""
Copyright(C) 2014-2025, Stamus Networks
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


from django.conf import settings
from django.contrib.auth.decorators import permission_required
from django.core.exceptions import PermissionDenied
from django.db.models import BooleanField, Case, When
from django.db.models.functions import Greatest
from django.http import HttpRequest, JsonResponse
from django.shortcuts import get_object_or_404, redirect

from scirius.utils import (
    convert_to_local,
    is_ajax,
    scirius_listing,
    scirius_render,
)
from suricata.tasks import check_task_perms, tasks_permission_required

MIDDLEWARE = __import__(settings.RULESET_MIDDLEWARE)


def status(request: HttpRequest):
    qlength = 20
    if request.GET.__contains__("length"):
        qlength = int(request.GET.get("length", 20))

    if is_ajax(request) or request.GET.__contains__("ajax"):
        tasks_list = MIDDLEWARE.task_models.CeleryTask.get_user_tasks(request)

        if not request.GET.__contains__("show_hidden"):
            tasks_list = tasks_list.filter(hidden=False)

        tasks_list = tasks_list.annotate(
            date=Greatest("finished", "eta", "created"),
            firsts=Case(When(status="running", then=True), default=False, output_field=BooleanField()),
        ).order_by("-firsts", "-date")[:qlength]
        task_in_progress = False

        tasks = []
        for task in tasks_list:
            if task.get_state() in ("STARTED", "RETRY", "RECEIVED"):
                task_in_progress = True
            can_edit = request.user.has_perm(task.get_task().REQUIRED_GROUPS["WRITE"])
            tasks.insert(0, task.display(full=False, can_edit=can_edit))

        if task_in_progress:
            data = {"msg": "Task(s) in progress", "tasks": tasks}
        else:
            data = {"msg": "No Task in progress", "tasks": tasks}

        return JsonResponse(data)

    context = {}
    return scirius_render(request, "rules/status.html", context)


@tasks_permission_required(MIDDLEWARE.task_models.RecurrentTask)
def stasks(request: HttpRequest, reccurent_task_qs):
    assocfn = {
        "Recurrent Task": {"table": MIDDLEWARE.tables.RecurrentTaskTable, "manage_links": {}, "action_links": {}}
    }

    extra_params = {}
    if MIDDLEWARE.__name__ != "suricata":
        extra_params.update({"template": f"{MIDDLEWARE.__name__}/object_list.html"})

    return scirius_listing(request, reccurent_task_qs.exclude(task="NotebookGenerationTask"), assocfn, **extra_params)


@tasks_permission_required(MIDDLEWARE.task_models.CeleryTask)
def task(request: HttpRequest, task_id):
    t = get_object_or_404(MIDDLEWARE.task_models.CeleryTask, pk=task_id)

    if request.method == "POST":
        raise PermissionDenied

    context = {"task": t.display()}
    return scirius_render(request, "rules/task.html", context)


@tasks_permission_required(MIDDLEWARE.task_models.CeleryTask)
def revoke_task(request: HttpRequest, task_id):
    t = get_object_or_404(MIDDLEWARE.task_models.CeleryTask, pk=task_id)

    if request.method == "GET":
        raise PermissionDenied

    t.revoke()
    context = {"success": "Revocation succeeded", "task": t.display()}

    return scirius_render(request, "rules/task.html", context)


@permission_required("rules.configuration_view", raise_exception=True)
@tasks_permission_required(MIDDLEWARE.task_models.RecurrentTask)
def scheduledtask(request: HttpRequest, task_id: int):
    stask = get_object_or_404(MIDDLEWARE.task_models.RecurrentTask, pk=task_id)
    task = stask.get_task()
    details = task.display_details()
    task_options = task.task_options
    task_options.pop("overrided_params", None)

    can_edit = check_task_perms(
        request, MIDDLEWARE.task_models.RecurrentTask, stask.pk, raise_exception=False
    ).exists() and request.user.has_perm("rules.configuration_edit")

    context = {"scheduledtask": stask, "task": details, "can_edit": can_edit, "task_options": task_options}
    return scirius_render(request, "rules/scheduledtask.html", context)


@permission_required("rules.configuration_edit", raise_exception=True)
@tasks_permission_required(MIDDLEWARE.task_models.RecurrentTask)
def delete_scheduledtask(request: HttpRequest, task_id: int):
    stask = get_object_or_404(MIDDLEWARE.task_models.RecurrentTask, pk=task_id)
    if request.method == "POST":
        stask.delete()
        page = MIDDLEWARE.common.get_redirect_for_stask(stask.task)
        return redirect(page)
    context = {"scheduledtask": stask, "task": stask.get_task().display(), "mode": "deletion"}
    return scirius_render(request, "rules/scheduledtask.html", context)


@permission_required("rules.configuration_edit", raise_exception=True)
@tasks_permission_required(MIDDLEWARE.task_models.RecurrentTask)
def edit_scheduledtask(request: HttpRequest, task_id: int):
    stask = get_object_or_404(MIDDLEWARE.task_models.RecurrentTask, pk=task_id)
    form = MIDDLEWARE.forms.EditRecurrentTaskForm(
        request.POST if request.method == "POST" else None, instance=stask, request=request
    )
    task_options = stask.get_task().task_options
    task_options.pop("overrided_params", None)

    context = {
        "scheduledtask": stask,
        "task": stask.get_task().display(),
        "mode": "edition",
        "form": form,
        "task_options": task_options,
        "recurrence": True,
        "schedule": True,
        "recurrence_param": stask.recurrence,
        "schedule_param": convert_to_local(stask.scheduled, request.user).strftime("%Y/%m/%d %H:%M"),
        "monthly": True,
    }

    if request.method == "POST":
        if form.is_valid():
            form.save()
            return redirect(MIDDLEWARE.common.stask_redirection(stask.task))
        context.update(
            {
                "error": f"Invalid form: {form.errors.as_text()}",
                "recurrence_param": form.cleaned_data["recurrence"],
                "schedule_param": convert_to_local(form.cleaned_data["scheduled"], request.user).strftime(
                    "%Y/%m/%d %H:%M"
                ),
            }
        )
    return scirius_render(request, "rules/scheduledtask.html", context)
