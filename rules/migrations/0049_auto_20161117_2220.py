# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rules', '0048_custom_es'),
    ]

    operations = [
        migrations.CreateModel(
            name='Transformation',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('type', models.CharField(max_length=12, choices=[(b'drop', b'Drop'), (b'filestore', b'Filestore')])),
                ('ruleset', models.ForeignKey(to='rules.Ruleset')),
            ],
        ),
        migrations.AddField(
            model_name='rule',
            name='transformations',
            field=models.ManyToManyField(to='rules.Transformation'),
        ),
    ]
