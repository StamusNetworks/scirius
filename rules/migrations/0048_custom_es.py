# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import rules.models


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
            name='elasticsearch_address',
            field=models.CharField(default=b'elasticsearch:9200', help_text=b'Elasticsearch address of the form "host:port".', max_length=200, blank=True, validators=[rules.models.validate_proxy]),
        ),
    ]
