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
import tarfile
import tempfile
from shutil import rmtree
from time import strftime

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from rules.es_data import ESData


class Command(BaseCommand, ESData):
    help = 'Remove Kibana dashboards.'

    def __init__(self, *args, **kw):
        BaseCommand.__init__(self, *args, **kw)
        ESData.__init__(self)

    def handle(self, *args, **options):
        self.kibana_clear()
        self.stdout.write('Kibana dashboards removed successfully')
