# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('rules', '0038_auto_20150516_0912'),
    ]

    operations = [
        migrations.AddField(
            model_name='ruleset',
            name='errors',
            field=models.TextField(blank=True),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='ruleset',
            name='need_test',
            field=models.BooleanField(default=True),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='ruleset',
            name='validity',
            field=models.BooleanField(default=True),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='category',
            name='created_date',
            field=models.DateTimeField(default=django.utils.timezone.now, verbose_name=b'date created'),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='sourceatversion',
            name='updated_date',
            field=models.DateTimeField(default=django.utils.timezone.now, verbose_name=b'date updated', blank=True),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='sourceupdate',
            name='created_date',
            field=models.DateTimeField(default=django.utils.timezone.now, verbose_name=b'date of update', blank=True),
            preserve_default=True,
        ),
    ]
