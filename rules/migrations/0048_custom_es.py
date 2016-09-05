# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rules', '0047_proxy_validation'),
    ]

    operations = [
        migrations.AddField(
            model_name='systemsettings',
            name='custom_elasticsearch',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='systemsettings',
            name='elasticsearch_url',
            field=models.URLField(default=b'http://elasticsearch:9200/', blank=True),
        ),
    ]
