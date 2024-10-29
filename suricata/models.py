"""
Copyright(C) 2014, Stamus Networks
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


from django.db import models
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.conf import settings
from django.urls import reverse
from django.contrib.auth.models import User
import pytz

# Create your models here.
import os
import json
import socket
from copy import deepcopy
from datetime import datetime, timedelta

from rules.models import Ruleset, Rule, export_iprep_files
from suricata import tasks

from celery import result


MIDDLEWARE = __import__(settings.RULESET_MIDDLEWARE)


def validate_hostname(value):
    if ' ' in value:
        raise ValidationError('"%s" contains space' % value)


class Suricata(models.Model):
    name = models.CharField(max_length=100, unique=True, validators=[validate_hostname])
    descr = models.CharField(max_length=400)
    created_date = models.DateTimeField('date created')
    updated_date = models.DateTimeField('date updated', blank=True)
    ruleset = models.ForeignKey(Ruleset, blank=True, null=True, on_delete=models.SET_NULL)

    editable = True

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs) -> None:
        if not self.pk:
            self.created_date = timezone.now()
        self.updated_date = timezone.now()

        return super().save(*args, **kwargs)

    def generate(self):
        # FIXME extract archive file for sources
        # generate rule file
        ravs = self.ruleset.to_buffer()
        # write to file

        with open(os.path.join(settings.SURICATA_OUTPUT_DIRECTORY, 'scirius.rules'), 'w') as rfile:
            rfile.write(ravs)
        # export files at version
        cats_content, iprep_content = self.ruleset.export_files(settings.SURICATA_OUTPUT_DIRECTORY)
        # FIXME gruick
        with open(os.path.join(settings.SURICATA_OUTPUT_DIRECTORY, 'rules.json'), 'w') as rfile:
            for rule in Rule.objects.all():
                dic = {'sid': rule.pk, 'created': str(rule.created), 'updated': str(rule.updated)}
                rfile.write(json.dumps(dic) + '\n')
        # Export IPrep
        export_iprep_files(settings.SURICATA_OUTPUT_DIRECTORY, cats_content, iprep_content)

    def push(self):
        # For now we just create a file asking for reload
        # It will cause an external script to reload suricata rules
        reload_file = os.path.join(settings.SURICATA_OUTPUT_DIRECTORY, "scirius.reload")
        if os.path.isfile(reload_file):
            return False
        with open(reload_file, 'w') as rfile:
            rfile.write(str(timezone.now()))
            rfile.close()
        # In case user has changed configuration file before reloading
        self.ruleset.needs_test()
        return True

    def get_absolute_url(self):
        return reverse('suricata_index')


def get_probe_hostnames(limit=10):
    if settings.SURICATA_NAME_IS_HOSTNAME:
        return [socket.gethostname()]

    suricata = Suricata.objects.all()
    if suricata is not None:
        return [suricata[0].name]

    return None


class CeleryTaskResultBase(models.Model):
    STATUS = (
        ('failed', 'Failure'),
        ('unreachable', 'Unreachable'),
        ('warning', 'Warning'),
        ('success', 'Success'),
    )
    date = models.DateTimeField('execution date', auto_now_add=True)
    status = models.CharField(max_length=15, choices=STATUS)
    message = models.TextField(blank=True, null=True)
    retry_no = models.PositiveIntegerField(default=0)

    class Meta:
        abstract = True


class CeleryTaskResult(CeleryTaskResultBase):
    task = models.ForeignKey('suricata.CeleryTask', on_delete=models.CASCADE)


class CeleryTaskBase(models.Model):
    STATUS = (
        ('scheduled', 'Scheduled'),
        ('running', 'Running'),
        ('finished', 'Finished'),
        ('revoked', 'Canceled'),
    )
    celery_id = models.CharField(max_length=36, blank=True, null=True)
    task = models.CharField(max_length=150)
    task_options = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=15, choices=STATUS, default='scheduled')
    is_recurrent = models.BooleanField(default=False)
    hidden = models.BooleanField(default=False)
    fired = models.DateTimeField('last fired date', blank=True, null=True)
    eta = models.DateTimeField(blank=True, null=True)
    finished = models.DateTimeField(blank=True, null=True)
    created = models.DateTimeField('creation date', auto_now_add=True)
    retry = models.PositiveIntegerField(default=0)
    success = models.BooleanField(default=True)
    run_from_command = models.BooleanField(default=False)
    user = models.ForeignKey(
        User, default=None,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='%(class)s_%(app_label)s')

    class Meta:
        abstract = True

    def __str__(self):
        return 'CTask %i %s %s' % (self.id, self.task, self.task_options)

    @staticmethod
    def get_user_tasks(request, users=None, recurrent=False):
        if users is None:
            users = [request.user]
        tasks_name = tasks.get_tasks(request)
        klass = MIDDLEWARE.models.CeleryTask if not recurrent else MIDDLEWARE.models.RecurrentTask
        tasks_list = klass.objects.filter(is_recurrent=recurrent, task__in=tasks_name)
        tasks_list |= klass.objects.filter(is_recurrent=recurrent, user__in=users)
        return tasks_list

    @classmethod
    def _create(cls, task, **kwargs):
        _kwargs = deepcopy(kwargs)
        recurrence = _kwargs.pop('recurrence', None)
        schedule = _kwargs.pop('schedule', None)
        user = _kwargs.pop('user', None)
        run_from_command = _kwargs.pop('run_from_command', False)
        rtask_parent = _kwargs.pop('rtask_parent', None)
        task_options = json.dumps(_kwargs)
        run_now = False

        if recurrence:
            if schedule is None:
                schedule = timezone.now()
                run_now = True
            t = MIDDLEWARE.models.RecurrentTask.objects.create(
                task=task,
                task_options=task_options,
                recurrence=recurrence,
                scheduled=schedule
            )
        else:
            t = MIDDLEWARE.models.CeleryTask.objects.create(
                task=task,
                task_options=task_options,
                run_from_command=run_from_command,
                rtask_parent=rtask_parent
            )

        t.hidden = t.get_task_class().HIDDEN and (not t.get_task_class().SHOW_IN_PENDING)
        t.user = user
        t.save()
        return t, run_now

    @staticmethod
    def new(task, **kwargs):
        t, run_now = MIDDLEWARE.models.CeleryTask._create(task, **kwargs)
        if run_now:
            t.schedule_run()
        return t

    @classmethod
    def spawn(cls, task, **kwargs):
        t = cls.new(task, **kwargs)
        if not t.is_recurrent:
            eta = kwargs.get('schedule')
            task = t.signature().apply_async(args=(t.id,), eta=eta)
            if eta:
                t.eta = eta
            t.celery_id = task.id
            t.save()
        return t

    def run(self):
        self.get_task().run()

    def add_result(self, _, status, msg=None, **kwargs):
        res, created = MIDDLEWARE.models.CeleryTaskResult.objects.get_or_create(
            task=self,
            retry_no=self.retry,
            defaults={'status': status, 'message': msg},
            **kwargs
        )

        if not created:
            if msg:
                if res.message:
                    res.message += '\n' + msg
                else:
                    res.message = msg

            if status != 'success':
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
        self.status = 'finished'
        self.finished = timezone.now()
        success_count = CeleryTaskResult.objects.filter(task=self, status__in=('success', 'warning')).count()

        if success_count == 0:
            self.success = False
        else:
            self.success = True

    def revoke_children(self):
        for child in self.children.all():
            child.revoke()

    def get_state(self):
        if self.status == 'revoked':
            return 'REVOKED'

        # https://git.stamus-networks.com/devel/scirius/-/issues/6214#note_119650
        # Avoid race condition when task has just been created
        # and celery_id is not yet set
        if self.celery_id is None:
            return 'PENDING'

        r = result.AsyncResult(self.celery_id)

        if r.state == 'RETRY' and self.status == 'running':
            return 'STARTED'

        if r.state == 'PENDING':
            if self.status == 'scheduled':
                return 'RECEIVED'
            elif self.status == 'finished':
                # Task is unknown to celery, so it returnns state PENDING (from an old celery version)
                if self.celerytaskresult_set.filter(status='warning').count() == 0:
                    return 'SUCCESS'
                else:
                    return 'WARNING'
            else:
                return 'STARTED'
        if r.state == 'SUCCESS':
            if self.success:
                if self.celerytaskresult_set.filter(status='warning').count() == 0:
                    return 'SUCCESS'
                else:
                    return 'WARNING'
            else:
                return 'FAILURE'
        return r.state

    def _date_to_ms(self, date):
        if date is None:
            return None
        return (date - datetime(1970, 1, 1, tzinfo=pytz.utc)).total_seconds() * 1000.0

    def _format_msg(self, msg):
        if msg is None:
            return ''
        last_lines = msg.strip().splitlines()[-15:]
        return '\n'.join(last_lines)

    def display(self, full=True, can_edit=False, **kwargs):
        state = self.get_state()

        runtime = None
        if state != 'REVOKED':
            if self.fired:
                if self.finished:
                    # finished or fired can be None when parent task failed
                    runtime = (self.finished - self.fired).seconds
                else:
                    runtime = (timezone.now() - self.fired).seconds

        retry = None
        if self.retry > 1 or state == 'RETRY':
            retry = self.retry - 1

        task = {
            'id': self.id,
            'celery_id': self.celery_id,
            'state': state,
            'runtime': runtime,
            'retries': retry,
            'eta_time': self.eta,
            'created_time': self.created,
            'start_time': self.fired,
            'end_time': self.finished,
            'user': self.user.username if self.user else 'Unknown user',
            'run_from_command': self.run_from_command,
            'can_edit': can_edit
        }

        if not full:
            for field in ('eta_time', 'start_time', 'end_time', 'created_time'):
                task[field] = self._date_to_ms(task[field])

        if full and state != 'SUCCESS':
            last_task = MIDDLEWARE.models.CeleryTaskResult.objects.filter(
                task=self,
                **kwargs
            ).order_by('-date')
            if last_task.count():
                task['failed_msg'] = self._format_msg(last_task[0].message)

        task.update(self.get_task().display())
        return task

    def revoke(self):
        self.status = 'revoked'
        self.eta = None
        self.save()
        for child in self.children.all():
            child.revoke()


class CeleryTask(CeleryTaskBase):
    children = models.ManyToManyField('self', related_name='parents', symmetrical=False)
    rtask_parent = models.ForeignKey(
        'suricata.RecurrentTask',
        related_name='rtask_children',
        null=True, blank=True,
        on_delete=models.SET_NULL)

    def get_task_class(self):
        if not hasattr(tasks, self.task):
            raise Exception('Invalid task type: %s' % self.task)

        _class = getattr(tasks, self.task)
        if not issubclass(_class, tasks.SciriusTask):
            raise Exception('Invalid task: %s' % self.task)

        return _class


class RecurrentTaskBase(models.Model):
    FREQUENCIES = (
        ('hourly', 'hourly'),
        ('daily', 'daily'),
        ('monthly', 'monthly')
    )
    scheduled = models.DateTimeField('schedule date')
    recurrence = models.CharField(max_length=20, choices=FREQUENCIES, default='daily')

    class Meta:
        abstract = True

    def __str__(self):
        return self.task

    def save(self, *args, **kwargs):
        self.is_recurrent = True
        super().save(*args, **kwargs)

    def get_absolute_url(self):
        return reverse('scheduledtask', args=[str(self.id)])

    def get_interval(self):
        if self.recurrence == 'hourly':
            return 3600
        elif self.recurrence == 'daily':
            return 86400
        elif self.recurrence == 'weekly':
            return 604800
        elif self.recurrence == 'monthly':
            # 3600 * 24 * 365 / 12
            return 2628000
        raise Exception('Invalid interval %s' % self.recurrence)

    def next_run_time(self, ctime):
        if ctime < self.scheduled:
            return self.scheduled
        delta = (ctime - self.scheduled).total_seconds()
        runs = int(delta / self.get_interval() + 1)
        return self.scheduled + timedelta(seconds=runs * self.get_interval())

    def schedule_run(self, eta=None, **kwargs):
        kwargs.update(json.loads(self.task_options))
        CeleryTask.spawn(
            self.task,
            schedule=eta,
            user=self.user,
            rtask_parent=self,
            **kwargs
        )

    def display(self, **kwargs):
        title = self.get_task().display().get('title')

        task = {
            'pk': self.pk,
            'task_options': self.task_options,
            'created': self.created,
            'task': self.task,
            'title': title,
            'scheduled': self.scheduled,
            'recurrence': self.recurrence,
            'user': self.user.pk if self.user else 'Unknown user',
            **kwargs
        }

        return task


class RecurrentTask(RecurrentTaskBase, CeleryTask):
    pass
