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
from rules.models import Ruleset, SourceAtVersion, Category, Transformation


class Command(BaseCommand):
    help = 'Create a ruleset and populate it with rules from existing sources'

    def add_arguments(self, parser):
        parser.add_argument('name', help='Source name')

    def handle(self, *args, **options):
        name = options['name']
        try:
            sourceat = SourceAtVersion.objects.all()
        except:
            raise CommandError("No SourceAtVersion is defined")
        try:
            categories = Category.objects.all()
        except:
            raise CommandError("No Category is defined")

        ruleset = Ruleset.objects.create(
            name=name,
            created_date=timezone.now(),
            updated_date=timezone.now()
        )

        # set default transformations
        ruleset.set_transformation(key=Transformation.LATERAL, value=Transformation.L_AUTO)
        ruleset.set_transformation(key=Transformation.TARGET, value=Transformation.T_AUTO)

        for source in sourceat:
            ruleset.sources.add(source)
        for cat in categories:
            ruleset.categories.add(cat)
        ruleset.save()
        self.stdout.write('Successfully created default ruleset "%s"' % name)
