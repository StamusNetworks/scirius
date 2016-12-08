# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rules', '0050_auto_20161128_2110'),
    ]

    operations = [
        migrations.AlterField(
            model_name='useraction',
            name='options',
            field=models.CharField(default=None, max_length=1000, null=True, blank=True),
        ),
    ]
