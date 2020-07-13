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


from django.core.management.base import BaseCommand, CommandError
from elasticsearch.exceptions import ConnectionError

from rules.es_data import ESData


class Command(BaseCommand, ESData):
    help = 'Remove all ElasticSearch data (except Kibana).'

    def __init__(self, *args, **kw):
        BaseCommand.__init__(self, *args, **kw)
        ESData.__init__(self)

    def handle(self, *args, **options):
        try:
            count = self.es_clear()
        except ConnectionError as e:
            self.stderr.write('Could not connect to Elasticsearch, please retry later.')
            raise CommandError(repr(e))
        if count:
            self.stdout.write('Data erased successfully (%i index%s deleted)' % (count, 'es' if count > 1 else ''))
        else:
            self.stdout.write('There is no index to erase')
