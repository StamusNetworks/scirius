# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import datetime


class Migration(migrations.Migration):

    dependencies = [
        ('rules', '0032_auto_20150103_1255'),
    ]

    operations = [
        migrations.AlterField(
            model_name='category',
            name='created_date',
            field=models.DateTimeField(default=datetime.datetime(2015, 1, 9, 23, 19, 11, 943180), verbose_name=b'date created'),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='sourceatversion',
            name='updated_date',
            field=models.DateTimeField(default=datetime.datetime(2015, 1, 9, 23, 19, 11, 942323), verbose_name=b'date updated', blank=True),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='sourceupdate',
            name='created_date',
            field=models.DateTimeField(default=datetime.datetime(2015, 1, 9, 23, 19, 11, 942747), verbose_name=b'date of update', blank=True),
            preserve_default=True,
        ),
    ]
