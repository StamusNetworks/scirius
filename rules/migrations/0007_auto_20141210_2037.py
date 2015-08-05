# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import datetime


class Migration(migrations.Migration):

    dependencies = [
        ('rules', '0006_auto_20141210_1846'),
    ]

    operations = [
        migrations.AlterField(
            model_name='category',
            name='created_date',
            field=models.DateTimeField(default=datetime.datetime(2014, 12, 10, 20, 37, 37, 259107), verbose_name=b'date created'),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='sourceatversion',
            name='updated_date',
            field=models.DateTimeField(default=datetime.datetime(2014, 12, 10, 20, 37, 37, 258426), verbose_name=b'date updated', blank=True),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='sourceupdate',
            name='created_date',
            field=models.DateTimeField(default=datetime.datetime(2014, 12, 10, 20, 37, 37, 258753), verbose_name=b'date of update', blank=True),
            preserve_default=True,
        ),
    ]
