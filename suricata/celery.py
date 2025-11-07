"""
Copyright(C) 2024, Stamus Networks
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

import logging
import os
import structlog

from celery import Celery
from celery.signals import setup_logging
from django.dispatch import receiver
from django_structlog.celery import signals
from django_structlog.celery.steps import DjangoStructLogInitStep

from django.conf import settings

# To start celery worker you can use
#   C_FORCE_ROOT=1 celery worker -A appliances -P solo
# -P solo is needed to avoid fork issue

# set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'scirius.settings')

app = Celery('scirius', broker=settings.CELERY_BROKER)
app.steps['worker'].add(DjangoStructLogInitStep)

# Using a string here means the worker will not have to
# pickle the object when using Windows.
app.config_from_object('django.conf:settings')
app.autodiscover_tasks(lambda: settings.INSTALLED_APPS)

extra_conf = {}
if settings.RULESET_MIDDLEWARE != 'suricata':
    extra_conf.update({
        'tasks_routes': {
            f'{settings.RULESET_MIDDLEWARE}.tasks.run_refresh_host_id_counts': {
                'queue': 'host_id'
            }
        }
    })

app.conf.update(
    CELERY_RESULT_BACKEND=settings.CELERY_RESULT_BACKEND,
    CELERY_TASK_SERIALIZER='json',
    CELERY_ACCEPT_CONTENT=['json'],  # Ignore other content
    CELERY_RESULT_SERIALIZER='json',
    **extra_conf
)


@app.task(bind=True)
def debug_task(self):
    print(('Request: {0!r}'.format(self.request)))


@setup_logging.connect
def receiver_setup_logging(loglevel, logfile, format, colorize, **kwargs):  # pragma: no cover  # noqa: A002
    logging.config.dictConfig(settings.LOGGING)

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.filter_by_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


@receiver(signals.modify_context_before_task_publish)
def receiver_modify_context_before_task_publish(sender, signal, context, task_routing_key=None, task_properties=None, **kwargs):
    keys_to_keep = {"request_id", "parent_task_id"}
    new_dict = {key_to_keep: context[key_to_keep] for key_to_keep in keys_to_keep if key_to_keep in context}
    context.clear()
    context.update(new_dict)
