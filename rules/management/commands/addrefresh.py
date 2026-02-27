"""
Copyright(C) 2025, Stamus Networks
Written by Eric Leblond <el@stamus-networks.com>

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

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from rules.models.model import Ruleset
from suricata.task_models import CeleryTask, RecurrentTask
from django.contrib.auth.models import User


class Command(BaseCommand):
    help = 'Add periodic refresh for a ruleset'

    def add_arguments(self, parser):
        parser.add_argument('name', help='Ruleset name')

    def handle(self, *args, **options):
        name = options['name']
        ruleset = Ruleset.objects.get(name=name)

        if not ruleset:
            raise CommandError(f'Ruleset "{name}" does not exist')

        # bail if we have already a recurring task
        if RecurrentTask.objects.exists():
            self.stdout.write('Periodic refresh task already exists, skipping creation')
            return

        # schedule the task to run the next hour at actual time
        now = timezone.now()
        scheduled_time = now.replace(day=now.day, hour=now.hour + 1, minute=now.minute, second=0, microsecond=0)

        # get superadmin user (unique user at the time being)
        user = User.objects.all()[0]

        CeleryTask.spawn(
            'UpdateGenerateRuleset',
            user=user,
            schedule=scheduled_time,
            recurrence='daily',
            update=True,
            generate=True,
            ruleset_pk=ruleset.pk
        )

        self.stdout.write(f'Successfully created periodic refresh for ruleset "{name}"')
