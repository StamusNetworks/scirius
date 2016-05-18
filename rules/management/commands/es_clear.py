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

from django.core.management.base import BaseCommand

from rules.es_data import ESData


class Command(BaseCommand, ESData):
    help = 'Remove all ElasticSearch data (except Kibana).'

    def __init__(self, *args, **kw):
        BaseCommand.__init__(self, *args, **kw)
        ESData.__init__(self)

    def handle(self, *args, **options):
        count = self.es_clear()
        if count:
            self.stdout.write('Data erased successfully (%i index%s deleted)' % (count, 'es' if count > 1 else ''))
        else:
            self.stdout.write('There is no index to erase')
