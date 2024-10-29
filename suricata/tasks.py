"""
Copyright(C) 2014-2024 Stamus Networks
Written by Nicolas Frisoni <nfrisoni@stamus-networks.com>

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
import json
from functools import wraps
from datetime import timedelta

from celery.schedules import crontab
from celery.utils.log import get_task_logger
from celery import shared_task, chord, group, chain

from suricata import celery_app
from rules.rest_permissions import HasGroupPermission
from rules.models import Ruleset, Source
from accounts.models import SciriusTokenUser

from django.utils import timezone
from django.conf import settings
from django.core.exceptions import SuspiciousOperation, ValidationError
from django.core.exceptions import PermissionDenied

import suricata.models


MIDDLEWARE = __import__(settings.RULESET_MIDDLEWARE)


logger = get_task_logger('celery_tasks')


class TaskFailure(Exception):
    pass


class TaskWarning(Exception):
    pass


def stask_exception_decorator(func):
    @wraps(func)
    def inner(*args, **kwargs):
        logger.info(f'{func.__name__} start')
        try:
            res = func(*args, **kwargs)
            logger.info(f'{func.__name__} end')
            return res
        except Exception:
            from traceback import format_exc
            logger.error(f'{func.__name__} failed:\n{format_exc()}')
            raise
    return inner


def task_exceptions_decorator(func):
    @wraps(func)
    def view(self):
        try:
            func(self)
        except TaskFailure as e:
            self.celery_task.add_result(None, 'failed', e)
            raise
        except TaskWarning as e:
            self.celery_task.add_result(None, 'warning', e)
            return
        except Exception:
            from traceback import format_exc
            self.celery_task.add_result(None, 'failed', format_exc())
            raise
    return view


def tasks_permission_required(klass):
    def decorator(func):
        @wraps(func)
        def view(request, task_id=None, *args, **kwargs):
            tasks_list = check_task_perms(request, klass, task_id)
            if task_id:
                return func(request, task_id, *args, **kwargs)
            return func(request, tasks_list, *args, **kwargs)
        return view
    return decorator


def rest_tasks_permission_required(klass):
    def decorator(func):
        @wraps(func)
        def view(self, request, pk=None, *args, **kwargs):
            tasks_list = check_task_perms(request, klass, pk)
            if pk:
                return func(self, request, pk, *args, **kwargs)
            return func(self, request, tasks_list, *args, **kwargs)
        return view
    return decorator


def check_task_perms(request, klass, task_id, raise_exception=True):
    recurrent = klass == MIDDLEWARE.models.RecurrentTask
    users = [request.user]
    if SciriusTokenUser.objects.filter(pk=request.user.sciriususer).exists():
        users = [request.user.sciriususer.sciriustokenuser.parent.user, request.user]
    tasks_list = MIDDLEWARE.models.CeleryTask.get_user_tasks(request, users=users, recurrent=recurrent)

    if task_id:
        if tasks_list.filter(pk=task_id).count() == 0:
            if raise_exception:
                raise PermissionDenied()
            return klass.objects.none()

    return tasks_list


def scirius_chord(parent, child):
    # Perform a celery chord() and set parent/children relationship on tasks
    if isinstance(parent, list):
        celery_parents = []
        for task in parent:
            task.children.add(child)
            celery_parents.append(task.signature())

        celery_parent = group(celery_parents)
    else:
        parent.children.add(child)
        celery_parent = parent.signature()

    return chord(celery_parent)(child.signature())


def scirius_chain(tasks):
    # Perform a celery chain() and set parent/children relationship on tasks
    celery_tasks = []
    for task_no, task in enumerate(tasks):
        if task_no + 1 < len(tasks):
            task.children.add(tasks[task_no + 1])
        celery_tasks.append(task.signature())

    return chain(celery_tasks)


def task_check_decorator(func):
    @wraps(func)
    def view(self):
        func(self)
        self.celery_task.add_result(None, 'success')
    return view


class SciriusTask:
    RETRY = True
    HIDDEN = False
    ICON = 'play-circle'
    SHOW_IN_PENDING = False
    TITLE = None

    def __init__(self, celery_task):
        self.celery_task = celery_task
        self.task_options = json.loads(celery_task.task_options)

    def _run(self, **_):
        raise NotImplementedError('_run must be overriden')

    @task_check_decorator
    @task_exceptions_decorator
    def run(self):
        self._run(**self.task_options)

    def _create_chain_step(self, seq):
        if len(seq) == 1:
            return seq[0]
        return group(seq)

    def chain(self, parents, children, *args):
        for parent in parents:
            parent.children.set(children)

        steps = [
            self._create_chain_step([parent.signature() for parent in parents]),
            self._create_chain_step([child.signature() for child in children])
        ]

        for items in args:
            return self.chain(children, items)
        return chain(steps)

    def _display_title(self):
        if self.TITLE:
            return self.TITLE
        return self.__class__.__name__

    def _display_icon(self):
        return self.ICON

    def display(self):
        _display = {
            'title': 'unknown',
            'icon': 'th'
        }

        for key, func in (('title', self._display_title),
                          ('icon', self._display_icon),
                          ('target', self._display_target)):
            try:
                _display[key] = func()
            except:
                pass

        return _display

    def _display_target(self):
        # will call next inherited class:
        # UpdateRuleset(SciriusTask, RulesetTask)
        # Then RulesetTask._display_target is called
        return super()._display_target()

    def display_details(self):
        return self.display()


class RulesetTask:
    def _display_target(self):
        try:
            ruleset = Ruleset.objects.get(pk=self.task_options['ruleset_pk'])
        except Ruleset.DoesNotExist:
            return 'Deleted ruleset'
        return ruleset.name


class UpdateRuleset(SciriusTask, RulesetTask):
    TITLE = 'Update ruleset'
    ICON = 'th'
    REQUIRED_GROUPS = {
        'READ': 'rules.ruleset_update_push',
        'WRITE': 'rules.ruleset_update_push'
    }

    def _run(self, ruleset_pk):
        ruleset = Ruleset.objects.filter(pk=ruleset_pk).first()
        if ruleset is None:
            raise Exception("Ruleset does not exist because it has been deleted")

        nb_sources = ruleset.sources.count()
        nb_errors = 0
        uri = None
        try:
            ruleset.update()
        except IOError as e:
            nb_errors += 1
            message = '%s' % (e,)
            if uri is not None:
                message = '%s: (%s)' % (e, uri)
            if nb_errors == nb_sources:
                raise TaskFailure(message)
            raise TaskWarning(message)


class BuildSuricataRuleset(SciriusTask, RulesetTask):
    TITLE = 'Build Ruleset'
    ICON = 'eye-open'
    REQUIRED_GROUPS = {
        'READ': 'rules.ruleset_update_push',
        'WRITE': 'rules.ruleset_update_push'
    }

    def _run(self, **_):
        suri = suricata.models.Suricata.objects.first()
        suri.generate()
        ret = suri.push()
        # set update_date
        suri.save()

        if ret is False:
            raise TaskWarning('Suricata restart already asked.')


class RulesetRulesAnalysis(SciriusTask, RulesetTask):
    TITLE = 'Ruleset rules analysis'
    ICON = 'zoom-in'
    REQUIRED_GROUPS = {
        'READ': 'rules.ruleset_update_push',
        'WRITE': 'rules.ruleset_update_push'
    }

    def _run(self, ruleset_pk):
        ruleset = Ruleset.objects.filter(pk=ruleset_pk).first()
        if ruleset is None:
            raise TaskFailure("Ruleset does not exist because it has been deleted")

        ruleset.analyse_rules()


class UpdateGenerateRuleset(SciriusTask):
    TITLE = 'Ruleset: update/generate'
    SHOW_IN_PENDING = True
    HIDDEN = True
    RETRY = False
    REQUIRED_GROUPS = {
        'READ': 'rules.ruleset_update_push',
        'WRITE': 'rules.ruleset_update_push'
    }

    def _run(self, update, generate, ruleset_pk, **_):
        if update:
            update = MIDDLEWARE.models.CeleryTask.new(
                'UpdateRuleset',
                user=self.celery_task.user,
                ruleset_pk=ruleset_pk
            )
            analyse = MIDDLEWARE.models.CeleryTask.new(
                'RulesetRulesAnalysis',
                ruleset_pk=ruleset_pk,
                user=self.celery_task.user
            )
            if generate:
                build = MIDDLEWARE.models.CeleryTask.new(
                    'BuildSuricataRuleset',
                    user=self.celery_task.user,
                    ruleset_pk=ruleset_pk
                )
                self.chain(
                    [update], [build, analyse]
                ).apply_async()
            else:
                self.chain(
                    [update], [analyse]
                ).apply_async()
        elif generate:
            MIDDLEWARE.models.CeleryTask.spawn(
                'BuildSuricataRuleset',
                user=self.celery_task.user,
                ruleset_pk=ruleset_pk
            )


class SourceTask:
    def _display_target(self):
        try:
            source = Source.objects.get(pk=self.task_options['source_pk'])
        except Source.DoesNotExist:
            return 'Deleted source'
        return source.name


class AddUpdateSourceTask(SourceTask):
    ICON = 'cloud-download'
    REQUIRED_GROUPS = {
        'READ': 'rules.ruleset_update_push',
        'WRITE': 'rules.ruleset_update_push'
    }

    def update_source(self, source_pk, add=False):
        source = Source.objects.get(pk=source_pk)
        try:
            source.update()
        except Exception as errors:
            if isinstance(errors, (IOError, OSError)):
                _msg = 'Can not fetch data'
            elif isinstance(errors, ValidationError):
                _msg = 'Source is invalid'
            elif isinstance(errors, SuspiciousOperation):
                _msg = 'Source is not correct'
            else:
                _msg = 'Error updating source'
            msg = '%s: %s' % (_msg, errors)
            if add:
                source.delete()
            raise TaskFailure(msg)


class UploadAddEditSourceTask(SourceTask):
    def upload(self, source_pk, path, add=False):
        source = Source.objects.get(pk=source_pk)
        try:
            with open(path, 'rb') as f:
                source.new_uploaded_file(f)
        except Exception as error:
            if isinstance(error, ValidationError):
                if hasattr(error, 'error_dict'):
                    error = ', '.join(['%s: %s' % (key, val) for key, val in error.message_dict.items()])
                elif hasattr(error, 'error_list'):
                    error = ', '.join(error.messages)
                else:
                    error = str(error)
            if add:
                source.delete()
            raise TaskFailure(error)
        finally:
            os.remove(path)


class UploadAddSourceTask(SciriusTask, UploadAddEditSourceTask):
    TITLE = 'Add/upload source'
    ICON = 'cloud-upload'
    RETRY = False
    REQUIRED_GROUPS = {
        'READ': 'rules.ruleset_update_push',
        'WRITE': 'rules.ruleset_update_push'
    }

    def _run(self, source_pk, path):
        self.upload(source_pk, path, add=True)


class UploadEditSourceTask(UploadAddSourceTask):
    TITLE = 'Update/upload source'

    def _run(self, source_pk, path):
        self.upload(source_pk, path)


class SourceTestTask(SciriusTask, SourceTask):
    TITLE = 'Test source'
    ICON = 'certificate'
    REQUIRED_GROUPS = {
        'READ': 'rules.source_view',
        'WRITE': 'rules.source_view'
    }

    def _parse_errors(self, errors):
        res = ''
        for error in errors:
            key = error['content'] if 'sid' not in error else error['sid']
            res += f'{key}: {error["message"]}\n'

        return res

    def _run(self, source_pk):
        source = Source.objects.get(pk=source_pk)
        test_results = source.test()

        if test_results['status'] is False:
            if test_results.get('errors', []):
                raise TaskFailure(self._parse_errors(test_results['errors']))
        else:
            if test_results.get('warnings', []):
                raise TaskWarning(self._parse_errors(test_results['warnings']))


class SourceUpdateParentTask(SciriusTask, SourceTask):
    TITLE = 'Source: update/test/analysis'
    SHOW_IN_PENDING = True
    HIDDEN = True
    RETRY = False
    REQUIRED_GROUPS = {
        'READ': 'rules.ruleset_update_push',
        'WRITE': 'rules.ruleset_update_push'
    }

    def _run(self, source_pk, path=None, add=False):
        source = Source.objects.get(pk=source_pk)

        main_task_params = {
            'task': 'UpdateSource',
            'source_pk': source_pk,
            'user': self.celery_task.user
        }

        if source.method == 'local':
            if path is None:
                # no new archive to upadte from
                return
            main_task_params.update({
                'task': 'UploadAddSourceTask' if add else 'UploadEditSourceTask',
                'path': path
            })
        else:
            if add:
                main_task_params['task'] = 'AddSourceTask'

        if source.datatype not in source.custom_data_type:
            update = MIDDLEWARE.models.CeleryTask.new(**main_task_params)

            test = MIDDLEWARE.models.CeleryTask.new(
                'SourceTestTask',
                source_pk=source_pk,
                user=self.celery_task.user
            )

            analysis = MIDDLEWARE.models.CeleryTask.new(
                'SourceRulesAnalysis',
                source_pk=source_pk,
                user=self.celery_task.user
            )

            self.chain(
                [update], [test, analysis]
            ).apply_async()
        else:
            update = MIDDLEWARE.models.CeleryTask.new(**main_task_params)
            analysis = MIDDLEWARE.models.CeleryTask.new(
                'SourceRulesAnalysis',
                source_pk=source_pk,
                user=self.celery_task.user
            )
            self.chain(
                [update], [analysis]
            ).apply_async()


class UpdateSource(SciriusTask, AddUpdateSourceTask):
    TITLE = 'Source update'

    def _run(self, source_pk):
        self.update_source(source_pk)


class AddSourceTask(SciriusTask, AddUpdateSourceTask):
    RETRY = False
    TITLE = 'Source add/update'

    def _run(self, source_pk):
        self.update_source(source_pk, add=True)


class SourceRulesAnalysis(SciriusTask, SourceTask):
    TITLE = 'Source rules analysis'
    ICON = 'zoom-in'
    REQUIRED_GROUPS = {
        'READ': 'rules.ruleset_update_push',
        'WRITE': 'rules.ruleset_update_push'
    }

    def _run(self, source_pk):
        source = Source.objects.get(pk=source_pk)
        source.analyse_rules()


# Internal cron function for task application
@celery_app.task
@stask_exception_decorator
def run_scheduled_tasks():
    if hasattr(MIDDLEWARE, 'license'):
        if MIDDLEWARE.license.grace_period_has_expired():
            return

    scheduled_tasks = MIDDLEWARE.models.RecurrentTask.objects.all()
    ctime = timezone.now()
    # we iterate on the scheduled_tasks
    for stask in scheduled_tasks:
        # nominal:
        #  compute the next run in the futur using 'created' and 'recurrence'
        #  check if next run is within 5 min
        #    if yes fire it: create the task and update 'fired'
        nrun = stask.next_run_time(ctime)

        if stask.fired and nrun - stask.fired <= timedelta(minutes=5):
            continue

        if nrun - ctime > timedelta(minutes=10):
            continue

        stask.schedule_run(eta=nrun)
        stask.fired = nrun
        stask.save()
        # FIXME implement the following
        # recovery:
        #  scirius has been down for a while and we must fire what we can
        #    compute previous run using 'created' and 'recurrence'
        #    check if 'fired' is older than previous run minus 5 minutes
        #    if yes fire it: create the task and update 'fired'


@celery_app.on_after_finalize.connect
def setup_periodic_tasks(**kwargs):
    celery_app.add_periodic_task(
        crontab(minute='*/5'),
        run_scheduled_tasks.s()
    )


@shared_task(bind=True, max_retries=3)
def run_celery_task(self, scirius_id):
    task = MIDDLEWARE.models.CeleryTask.objects.get(id=scirius_id)
    if task.status == 'revoked':
        return
    task.celery_id = self.request.id
    task.status = 'running'
    task.eta = None
    task.fired = timezone.now()
    # Hide task
    task.hidden = task.get_task_class().HIDDEN
    task.save()

    try:
        task.run()
    except Exception as e:
        if task.get_task_class().RETRY:
            task.eta = timezone.now() + timedelta(minutes=3)
            raise self.retry(exc=e)
        raise
    finally:
        task.set_finished()
        task.retry += 1
        task.save()

        # When the tassk failed and it's not to be retried, revoke children
        if not task.success and (not task.get_task_class().RETRY or (task.retry - 1) == self.max_retries):
            task.revoke_children()

    MIDDLEWARE.common.run_celery_task_extra(self, task)


def get_all_tasks():
    return (
        UpdateSource, SourceRulesAnalysis, UploadAddSourceTask, SourceTestTask,
        UploadEditSourceTask, AddSourceTask, UpdateRuleset, BuildSuricataRuleset,
        RulesetRulesAnalysis
    )


def get_tasks(request):
    action = None
    all_tasks = MIDDLEWARE.tasks.get_all_tasks()

    if request.method in HasGroupPermission.READ:
        action = 'READ'
    elif request.method in HasGroupPermission.WRITE:
        action = 'WRITE'
    else:
        raise Exception('Not implemented: {}'.format(request.method))

    tasks = []
    for task in all_tasks:
        if request.user.has_perm(task.REQUIRED_GROUPS[action]):
            tasks.append(task.__name__)

    return tasks
