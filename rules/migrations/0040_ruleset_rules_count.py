# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('rules', '0039_auto_20150805_1737'),
    ]

    operations = [
        migrations.AddField(
            model_name='ruleset',
            name='rules_count',
            field=models.IntegerField(default=0),
            preserve_default=True,
        ),
    ]
