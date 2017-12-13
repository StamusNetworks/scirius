# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rules', '0052_useraction_user'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='ruleset',
            name='nodrop_rules',
        ),
        migrations.RemoveField(
            model_name='ruleset',
            name='nofilestore_rules',
        ),
        migrations.RemoveField(
            model_name='ruleset',
            name='noreject_rules',
        ),
        migrations.AddField(
            model_name='ruleset',
            name='none_rules',
            field=models.ManyToManyField(related_name='rules_none', to='rules.Rule', blank=True),
        ),
    ]
