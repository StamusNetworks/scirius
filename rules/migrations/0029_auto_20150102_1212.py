# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import datetime


class Migration(migrations.Migration):

    dependencies = [
        ('rules', '0028_auto_20150101_2305'),
    ]

    operations = [
        migrations.AlterField(
            model_name='category',
            name='created_date',
            field=models.DateTimeField(default=datetime.datetime(2015, 1, 2, 12, 12, 59, 269605), verbose_name=b'date created'),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='sourceatversion',
            name='updated_date',
            field=models.DateTimeField(default=datetime.datetime(2015, 1, 2, 12, 12, 59, 268883), verbose_name=b'date updated', blank=True),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='sourceupdate',
            name='created_date',
            field=models.DateTimeField(default=datetime.datetime(2015, 1, 2, 12, 12, 59, 269229), verbose_name=b'date of update', blank=True),
            preserve_default=True,
        ),
    ]
