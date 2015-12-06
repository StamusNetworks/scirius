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

from django.test import TestCase

from django.utils import timezone

from models import Source, SourceAtVersion, Category

import tempfile
from shutil import rmtree

class SourceCreationTestCase(TestCase):
    def setUp(self):
        self.tmpdirname = tempfile.mkdtemp()
        with self.settings(GIT_SOURCES_BASE_DIRECTORY=self.tmpdirname):
            self.source = Source.objects.create(name="ET Open",
                                       method = "http",
                                       datatype = "sigs",
                                       uri="https://rules.emergingthreats.net/open/suricata-2.0.1/emerging.rules.tar.gz",
                                       created_date=timezone.now())

    def tearDown(self):
        rmtree(self.tmpdirname)

    def test_source_update(self):
        """Test source update"""
        self.source.update()
        self.assertEqual(len(SourceAtVersion.objects.filter(source = self.source)), 1)
        self.assertNotEqual(len(Category.objects.filter(source = self.source)), 0)
