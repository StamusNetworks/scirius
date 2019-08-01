from __future__ import unicode_literals
from django.core.management.base import BaseCommand, CommandError
from rules.models import Ruleset
from suricata.models import Suricata
from django.utils import timezone
import os

class Command(BaseCommand):
    help = 'Remove a suricata'

    def add_arguments(self, parser):
        parser.add_argument('name', help='Suricata name')

    def handle(self, *args, **options):
        name = options['name']
        suricata = Suricata.objects.get(name=name)
        suricata.delete()
        self.stdout.write('Successfully removed suricata "%s"' % suricata.name)
