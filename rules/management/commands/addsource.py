"""
Copyright(C) 2014-2018, Stamus Networks
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
    help = 'Create and update a source'

    def add_arguments(self, parser):
        parser.add_argument('name', help='Source name')
        parser.add_argument('uri', help='Uri of the source')
        parser.add_argument('method', help='Method to import the source (http)')
        parser.add_argument('datatype', help='Type of file to import (sig or sigs)')

    def handle(self, *args, **options):
        name = options['name']
        uri = options['uri']
        method = options['method']
        datatype = options['datatype']

        if method not in ['http', 'local']:
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
        if source.method == 'http':
            source.update()
        else:
            with open(uri, 'r') as f:
                if source.datatype == 'sigs':
                    source.handle_rules_in_tar(f)
                elif source.datatype == 'sig':
                    source.handle_rules_file(f)
        self.stdout.write('Successfully updated source "%s"' % name)
