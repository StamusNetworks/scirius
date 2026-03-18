"""
Copyright(C) 2014-2026, Stamus Networks
Developpers:
* Eric Leblond <eleblond@stamus-networks.com>
* Sebastien LUNDI <slundi@stamus-networks.com>

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

from typing import ClassVar
from django.conf import settings
from django.db import models
from django.http import HttpRequest
from django.utils import timezone
from django.urls import reverse
from django.contrib.auth.models import User
import pytz

import orjson
from copy import deepcopy
from datetime import datetime, timedelta

from suricata import tasks

from celery import result
from celery.utils.log import get_task_logger


celery_logger = get_task_logger("task_logger")


class CeleryTaskResultBase(models.Model):
    STATUS = (
        ("failed", "Failure"),
        ("unreachable", "Unreachable"),
        ("warning", "Warning"),
        ("success", "Success"),
    )
    date = models.DateTimeField("execution date", auto_now_add=True)
    status = models.CharField(max_length=15, choices=STATUS)
    message = models.TextField(blank=True, null=True)
    retry_no = models.PositiveIntegerField(default=0)

    class Meta:
        abstract = True


class CeleryTaskResult(CeleryTaskResultBase):
    task = models.ForeignKey("suricata.CeleryTask", on_delete=models.CASCADE)


class CeleryTaskBase(models.Model):
    LOGGER: ClassVar[dict[str, str]] = {"failed": "error", "warning": "warning", "success": "info"}
    STATUS = (
        ("scheduled", "Scheduled"),
        ("running", "Running"),
        ("finished", "Finished"),
        ("revoked", "Canceled"),
    )
    celery_id = models.CharField(max_length=36, blank=True, null=True)
    task = models.CharField(max_length=150)
    task_options = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=15, choices=STATUS, default="scheduled")
    is_recurrent = models.BooleanField(default=False)
    hidden = models.BooleanField(default=False)
    fired = models.DateTimeField("last fired date", blank=True, null=True)
    eta = models.DateTimeField(blank=True, null=True)
    finished = models.DateTimeField(blank=True, null=True)
    created = models.DateTimeField("creation date", auto_now_add=True)
    retry = models.PositiveIntegerField(default=0)
    success = models.BooleanField(default=True)
    run_from_command = models.BooleanField(default=False)
    user = models.ForeignKey(
        User, default=None, on_delete=models.SET_NULL, null=True, blank=True, related_name="%(class)s_%(app_label)s"
    )

    class Meta:
        abstract = True

    def __str__(self):
        return f"CTask {self.id} {self.task} {self.task_options}"

    @staticmethod
    def get_user_tasks(request: HttpRequest, users=None, recurrent: bool = False):
        if users is None:
            users = [request.user]
        tasks_name = tasks.get_tasks(request)
        MIDDLEWARE = __import__(settings.RULESET_MIDDLEWARE)
        klass = MIDDLEWARE.task_models.CeleryTask if not recurrent else MIDDLEWARE.task_models.RecurrentTask
        tasks_list = klass.objects.filter(is_recurrent=recurrent, task__in=tasks_name)
        tasks_list |= klass.objects.filter(is_recurrent=recurrent, user__in=users)
        return tasks_list

    @classmethod
    def _create(cls, task, **kwargs):
        MIDDLEWARE = __import__(settings.RULESET_MIDDLEWARE)
        _kwargs = deepcopy(kwargs)
        recurrence = _kwargs.pop("recurrence", None)
        schedule = _kwargs.pop("schedule", None)
        user = _kwargs.pop("user", None)
        run_from_command = _kwargs.pop("run_from_command", False)
        rtask_parent = _kwargs.pop("rtask_parent", None)
        task_options = orjson.dumps(_kwargs).decode('utf-8')
        run_now = False

        if recurrence:
            if schedule is None:
                schedule = timezone.now()
                run_now = True
            t = MIDDLEWARE.task_models.RecurrentTask.objects.create(
                task=task, task_options=task_options, recurrence=recurrence, scheduled=schedule
            )
        else:
            t = MIDDLEWARE.task_models.CeleryTask.objects.create(
                task=task, task_options=task_options, run_from_command=run_from_command, rtask_parent=rtask_parent
            )

        t.hidden = t.get_task_class().HIDDEN and (not t.get_task_class().SHOW_IN_PENDING)
        t.user = user
        t.save()
        return t, run_now

    @staticmethod
    def new(task, **kwargs):
        MIDDLEWARE = __import__(settings.RULESET_MIDDLEWARE)
        t, run_now = MIDDLEWARE.task_models.CeleryTask._create(task, **kwargs)
        if run_now:
            t.schedule_run()
        return t

    @classmethod
    def spawn(cls, task, **kwargs):
        t = cls.new(task, **kwargs)
        if not t.is_recurrent:
            eta = kwargs.get("schedule")
            task = t.signature().apply_async(args=(t.id,), eta=eta)
            if eta:
                t.eta = eta
            t.celery_id = task.id
            t.save()
        return t

    def run(self):
        self.get_task().run()

    def add_result(self, _: str, status: str, msg: str | None = None, **kwargs):
        MIDDLEWARE = __import__(settings.RULESET_MIDDLEWARE)
        res, created = MIDDLEWARE.task_models.CeleryTaskResult.objects.get_or_create(
            task=self, retry_no=self.retry, defaults={"status": status, "message": msg}, **kwargs
        )

        getattr(celery_logger, self.LOGGER.get(status, "info"))(f"Task {self.pk}, ({status}): {msg}")

        if not created:
            if msg:
                if res.message:
                    res.message += "\n" + msg
                else:
                    res.message = msg

            if status != "success":
                res.status = status

            res.save()

    def get_task(self):
        _class = self.get_task_class()
        return _class(self)

    def signature(self):
        task = tasks.run_celery_task.si(self.id)
        r = task.freeze()
        self.celery_id = r.task_id
        self.save()
        return task

    def set_finished(self):
        self.status = "finished"
        self.finished = timezone.now()
        success_count = CeleryTaskResult.objects.filter(task=self, status__in=("success", "warning")).count()

        if success_count == 0:
            self.success = False
        else:
            self.success = True

    def revoke_children(self):
        for child in self.children.all():
            child.revoke()

    def get_state(self) -> str:
        if self.status == "revoked":
            return "REVOKED"

        # https://git.stamus-networks.com/devel/scirius/-/issues/6214#note_119650
        # Avoid race condition when task has just been created
        # and celery_id is not yet set
        if self.celery_id is None:
            return "PENDING"

        r = result.AsyncResult(self.celery_id)

        if r.state == "RETRY" and self.status == "running":
            return "STARTED"

        if r.state == "PENDING":
            if self.status == "scheduled":
                return "RECEIVED"
            if self.status == "finished":
                # Task is unknown to celery, so it returnns state PENDING (from an old celery version)
                if self.celerytaskresult_set.filter(status="warning").count() == 0:
                    return "SUCCESS"
                return "WARNING"
            return "STARTED"
        if r.state == "SUCCESS":
            if self.success:
                if self.celerytaskresult_set.filter(status="warning").count() == 0:
                    return "SUCCESS"
                return "WARNING"
            return "FAILURE"
        return r.state

    def _date_to_ms(self, date: datetime | None):
        if date is None:
            return None
        return (date - datetime(1970, 1, 1, tzinfo=pytz.utc)).total_seconds() * 1000.0

    def _format_msg(self, msg):
        if msg is None:
            return ""
        last_lines = msg.strip().splitlines()[-15:]
        return "\n".join(last_lines)

    def display(self, full=True, can_edit=False, **kwargs) -> str:
        MIDDLEWARE = __import__(settings.RULESET_MIDDLEWARE)
        state = self.get_state()

        runtime = None
        if state != "REVOKED" and self.fired:
            runtime = ((self.finished - self.fired) if self.finished else (timezone.now() - self.fired)).seconds

        retry = None
        if self.retry > 1 or state == "RETRY":
            retry = self.retry - 1

        task = {
            "id": self.id,
            "celery_id": self.celery_id,
            "state": state,
            "runtime": runtime,
            "retries": retry,
            "eta_time": self.eta,
            "created_time": self.created,
            "start_time": self.fired,
            "end_time": self.finished,
            "user": self.user.username if self.user else "Unknown user",
            "run_from_command": self.run_from_command,
            "can_edit": can_edit,
        }

        if not full:
            for field in ("eta_time", "start_time", "end_time", "created_time"):
                task[field] = self._date_to_ms(task[field])

        if full and state != "SUCCESS":
            last_task = MIDDLEWARE.task_models.CeleryTaskResult.objects.filter(task=self, **kwargs).order_by("-date")
            if last_task.count():
                task["failed_msg"] = self._format_msg(last_task[0].message)

        task.update(self.get_task().display())
        return task

    def revoke(self):
        self.status = "revoked"
        self.eta = None
        self.save()
        for child in self.children.all():
            child.revoke()


class CeleryTask(CeleryTaskBase):
    children = models.ManyToManyField("self", related_name="parents", symmetrical=False)
    rtask_parent = models.ForeignKey(
        "suricata.RecurrentTask", related_name="rtask_children", null=True, blank=True, on_delete=models.SET_NULL
    )

    def get_task_class(self):
        if not hasattr(tasks, self.task):
            raise Exception(f"Invalid task type: {self.task}")

        _class = getattr(tasks, self.task)
        if not issubclass(_class, tasks.SciriusTask):
            raise Exception(f"Invalid task: {self.task}")

        return _class


class RecurrentTaskBase(models.Model):
    FREQUENCIES = (("hourly", "hourly"), ("daily", "daily"), ("monthly", "monthly"))
    scheduled = models.DateTimeField("schedule date")
    recurrence = models.CharField(max_length=20, choices=FREQUENCIES, default="daily")

    class Meta:
        abstract = True

    def __str__(self) -> str:
        return self.task

    def save(self, *args, **kwargs):
        self.is_recurrent = True
        super().save(*args, **kwargs)

    def get_absolute_url(self):
        return reverse("scheduledtask", args=[str(self.id)])

    def get_interval(self):
        if self.recurrence == "hourly":
            return 3600
        if self.recurrence == "daily":
            return 86400
        if self.recurrence == "weekly":
            return 604800
        if self.recurrence == "monthly":
            # 3600 * 24 * 365 / 12
            return 2628000
        raise Exception(f"Invalid interval {self.recurrence}")

    def next_run_time(self, ctime):
        if ctime < self.scheduled:
            return self.scheduled
        delta = (ctime - self.scheduled).total_seconds()
        runs = int(delta / self.get_interval() + 1)
        return self.scheduled + timedelta(seconds=runs * self.get_interval())

    def schedule_run(self, eta: datetime | None = None, **kwargs):
        kwargs.update(orjson.loads(self.task_options))
        CeleryTask.spawn(self.task, schedule=eta, user=self.user, rtask_parent=self, **kwargs)

    def display(self, **kwargs):
        title = self.get_task().display().get("title")

        return {
            "pk": self.pk,
            "task_options": self.task_options,
            "created": self.created,
            "task": self.task,
            "title": title,
            "scheduled": self.scheduled,
            "recurrence": self.recurrence,
            "user": self.user.pk if self.user else "Unknown user",
            **kwargs,
        }


class RecurrentTask(RecurrentTaskBase, CeleryTask):
    pass
