"""
Copyright(C) 2016, Stamus Networks
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


from django.core.management.base import BaseCommand

from rules.backup import SCBackup


class Command(BaseCommand):
    help = 'Create a backup.'

    def add_arguments(self, parser):
        parser.add_argument(
            '-a', '--all-history',
            default=False,
            action='store_true',
            dest='all_history',
            help='Backup with all git history'
        )

    def handle(self, *_, **options):
        backup = SCBackup(all_history=options['all_history'])
        backup.run()
