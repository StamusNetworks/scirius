# -*- coding: utf-8 -*-


from django.db import migrations, models
import rules.models


class Migration(migrations.Migration):

    dependencies = [
        ('rules', '0046_source_cert_verif'),
    ]

    operations = [
        migrations.AlterField(
            model_name='systemsettings',
            name='http_proxy',
            field=models.CharField(default=b'', help_text=b'Proxy address of the form "host:port".', max_length=200, blank=True, validators=[rules.models.validate_proxy]),
        ),
        migrations.AlterField(
            model_name='systemsettings',
            name='https_proxy',
            field=models.CharField(default=b'', max_length=200, blank=True, validators=[rules.models.validate_proxy]),
        ),
    ]
