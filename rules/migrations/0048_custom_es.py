# -*- coding: utf-8 -*-


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
            name='elasticsearch_url',
            field=models.CharField(default=b'http://elasticsearch:9200/', max_length=200, blank=True, validators=[rules.models.validate_url]),
        ),
    ]
