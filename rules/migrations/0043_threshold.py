# -*- coding: utf-8 -*-


from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rules', '0042_rule_state_in_source'),
    ]

    operations = [
        migrations.CreateModel(
            name='Threshold',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('descr', models.CharField(max_length=400, blank=True)),
                ('threshold_type', models.CharField(default=b'suppress', max_length=20, choices=[(b'threshold', b'threshold'), (b'event_filter', b'event_filter'), (b'suppress', b'suppress')])),
                ('type', models.CharField(default=b'limit', max_length=20, choices=[(b'limit', b'limit'), (b'threshold', b'threshold'), (b'both', b'both')])),
                ('gid', models.IntegerField(default=1)),
                ('track_by', models.CharField(default=b'by_src', max_length=10, choices=[(b'by_src', b'by_src'), (b'by_dst', b'by_dst')])),
                ('net', models.CharField(max_length=100, blank=True)),
                ('count', models.IntegerField(default=1)),
                ('seconds', models.IntegerField(default=60)),
                ('rule', models.ForeignKey(default=None, to='rules.Rule')),
                ('ruleset', models.ForeignKey(default=None, to='rules.Ruleset')),
            ],
        ),
    ]
