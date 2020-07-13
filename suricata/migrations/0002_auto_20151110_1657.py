# -*- coding: utf-8 -*-


from django.db import models, migrations
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('suricata', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='suricata',
            name='ruleset',
            field=models.ForeignKey(on_delete=django.db.models.deletion.SET_NULL, blank=True, to='rules.Ruleset', null=True),
        ),
    ]
