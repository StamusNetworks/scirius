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

from django.core.management.base import BaseCommand, CommandError
from rules.models import Ruleset
from suricata.models import Suricata
from datetime import datetime

class Command(BaseCommand):
    args = 'name description output_dir ruleset'
    help = 'Create a ruleset and populate it with rules from existing sources'

    def handle(self, *args, **options):
        (name, descr, output, nruleset) = args
        try:
            ruleset = Ruleset.objects.filter(name = nruleset)[0]
        except:
            raise CommandError('No Ruleset with name "%s" found' % (nruleset))
        suricata = Suricata.objects.create(
            name = name,
            descr = descr,
            output_directory = output,
            ruleset = ruleset,
            created_date = datetime.now(),
            updated_date = datetime.now()
            )
        self.stdout.write('Successfully created suricata "%s"' % suricata.name)

