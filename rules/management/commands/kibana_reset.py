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
    help = 'Deletes and recreates Kibana dashboards.'

    def __init__(self, *args, **kw):
        BaseCommand.__init__(self, *args, **kw)
        ESData.__init__(self)

    def _get_kibana_files(self, _type):
        files = []
        for _dir in os.listdir(settings.KIBANA_DASHBOARDS_PATH):
            idx_path = os.path.join(settings.KIBANA_DASHBOARDS_PATH, _dir, _type)
            if os.path.isdir(idx_path):
                for _file in os.listdir(idx_path):
                    if not _file.endswith('.json'):
                        continue
                    _file = os.path.join(idx_path, _file)
                    files.append(_file)
        return files       

    def handle(self, *args, **options):
        if not os.path.isdir(settings.KIBANA_DASHBOARDS_PATH):
            raise CommandError('Please make sure Kibana dashboards are installed at %s' % settings.KIBANA_DASHBOARDS_PATH)

        if self._get_kibana_files('index-pattern') == []:
            raise CommandError('Please make sure Kibana dashboards are installed at %s: no index-pattern found' % settings.KIBANA_DASHBOARDS_PATH)

        self._kibana_remove('dashboard', {'query': {'match': {'title': 'SN *'}}})
        self._kibana_remove('visualization', {'query': {'match': {'title': 'SN *'}}})
        self._kibana_remove('search', {'query': {'match': {'title': 'SN *'}}})
        self._kibana_remove('index-pattern', {'query': {'match_all': {}}})

        for _type in ('index-pattern', 'search', 'visualization', 'dashboard'):
            for _file in self._get_kibana_files(_type):
                self._kibana_inject(_type, _file)

        self._kibana_set_default_index(u'logstash-*')
        self.stdout.write('Kibana dashboards reloaded successfully')
