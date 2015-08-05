# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import datetime


class Migration(migrations.Migration):

    dependencies = [
        ('rules', '0035_auto_20150202_0937'),
    ]

    operations = [
        migrations.CreateModel(
            name='SystemSettings',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('use_http_proxy', models.BooleanField(default=False)),
                ('http_proxy', models.CharField(default=b'', max_length=200, blank=True)),
                ('https_proxy', models.CharField(default=b'', max_length=200, blank=True)),
                ('use_elasticsearch', models.BooleanField(default=True)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.AlterField(
            model_name='category',
            name='created_date',
            field=models.DateTimeField(default=datetime.datetime(2015, 2, 3, 14, 21, 41, 717852), verbose_name=b'date created'),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='sourceatversion',
            name='updated_date',
            field=models.DateTimeField(default=datetime.datetime(2015, 2, 3, 14, 21, 41, 717121), verbose_name=b'date updated', blank=True),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='sourceupdate',
            name='created_date',
            field=models.DateTimeField(default=datetime.datetime(2015, 2, 3, 14, 21, 41, 717462), verbose_name=b'date of update', blank=True),
            preserve_default=True,
        ),
    ]
