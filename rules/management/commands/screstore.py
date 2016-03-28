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

from django.core.management.base import BaseCommand, CommandError
from django.conf import settings

import sys

from rules.backup import SCRestore, SCBackupException

class Command(BaseCommand):
    args = 'filepath'
    help = 'Restore a backup directory. This will erase all data.'

    def handle(self, *args, **options):
        if len(args):
            [filepath] = args
            if len(filepath[0]) == 0:
                filepath = None
        else:
            filepath = None
        restore = SCRestore(filepath = filepath)
        try:
            restore.run()
        except SCBackupException as err:
            sys.stderr.write("%s\n" % (str(err)))
            sys.exit(-1)
