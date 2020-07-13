'''
Copyright(C) 2016, Stamus Networks
Written by Laurent Defert <lds@stamus-networks.com>

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
'''


import os

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from rules.es_data import ESData


class Command(BaseCommand, ESData):
    help = 'Import Kibana dashboards.'

    def __init__(self, *args, **kw):
        BaseCommand.__init__(self, *args, **kw)
        ESData.__init__(self)

    def add_arguments(self, parser):
        parser.add_argument('source',
            help='Path to kibana dashboards directory')

    def handle(self, *args, **options):
        source = options['source']
        if not os.path.isdir(source):
            raise CommandError('%s is not a valid directory' % source)

        if self._get_kibana_files(source, 'dashboard') == []:
            raise CommandError('Directory %s does not contain any dashboard' % source)

        for _type in ('search', 'visualization', 'dashboard'):
            for _file in self._get_kibana_files(source, _type):
                self._kibana_inject(_type, _file)

        self.stdout.write('Kibana dashboards reloaded successfully')
