# -*- coding: utf-8 -*-


from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('rules', '0041_source_authkey'),
    ]

    operations = [
        migrations.AddField(
            model_name='rule',
            name='state_in_source',
            field=models.BooleanField(default=True),
            preserve_default=True,
        ),
    ]
