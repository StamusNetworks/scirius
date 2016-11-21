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
from django.utils import timezone
from rules.models import Source

class Command(BaseCommand):
    args = 'name uri method datatype'
    help = 'Create and update a source'

    def handle(self, *args, **options):
        (name, uri, method, datatype) = args
        if method not in ['http']:
            raise CommandError("Method '%s' is not supported" % (method))
        if datatype not in ['sigs', 'sig']:
            raise CommandError("Data type '%s' is not supported" % (datatype))
        source = Source.objects.create(
            name = name,
            uri = uri,
            method = method,
            created_date = timezone.now(),
            datatype = datatype)
        self.stdout.write('Successfully created source "%s"' % name)
        source.update()
        self.stdout.write('Successfully update source "%s"' % name)
