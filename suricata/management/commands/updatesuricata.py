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
from suricata.models import Suricata

class Command(BaseCommand):
    help = 'Update Suricata ruleset and apply it'

    def handle(self, *args, **options):
        suricata = Suricata.objects.all()[0]
        try:
            suricata.ruleset.update()
        except Exception as detail:
            self.stderr.write('Unable to update ruleset for suricata "%s": %s' %
                                (suricata.name, detail))
        suricata.generate()
        suricata.push()
        self.stdout.write('Successfully pushed ruleset to suricata "%s"' % suricata.name)

