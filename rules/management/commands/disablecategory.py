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

from __future__ import unicode_literals
from django.core.management.base import BaseCommand, CommandError
from rules.models import Ruleset, SourceAtVersion, Category

class Command(BaseCommand):
    help = 'Remove a category from a ruleset'

    def add_arguments(self, parser):
        parser.add_argument('ruleset', help='Ruleset name')
        parser.add_argument('category', help='Category name')

    def handle(self, *args, **options):
        ruleset = options['ruleset']
        catname = options['category']
        
        try:
            ruleset = Ruleset.objects.filter(name = ruleset)
            ruleset = ruleset[0]
        except:
            raise CommandError("No ruleset with name '%s' is defined" % (ruleset))
        try:
            categories = Category.objects.filter(name = catname)
        except:
            raise CommandError("No Category is defined")
        for cat in categories:
            ruleset.categories.remove(cat)
        ruleset.save()
        self.stdout.write('Successfully removed "%s" from ruleset "%s"' % (catname, ruleset))

