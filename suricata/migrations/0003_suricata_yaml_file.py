# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import os

def gen_yaml_file(apps, schema_editor):
    Suricata = apps.get_model('suricata', 'Suricata')
    for row in Suricata.objects.all():
        row.yaml_file = os.path.join(os.path.split(row.output_directory.rstrip("/"))[0], 'suricata.yaml')
        row.save()

class Migration(migrations.Migration):

    dependencies = [
        ('suricata', '0002_auto_20151110_1657'),
    ]

    operations = [
        migrations.AddField(
            model_name='suricata',
            name='yaml_file',
            field=models.CharField(default='/etc/default/suricata.yaml', max_length=400),
            preserve_default=False,
        ),
        migrations.RunPython(gen_yaml_file, reverse_code=migrations.RunPython.noop),
    ]
