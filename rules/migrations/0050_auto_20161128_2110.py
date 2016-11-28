# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import django.utils.timezone
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('contenttypes', '0002_remove_content_type_name'),
        ('rules', '0049_auto_20161121_2342'),
    ]

    operations = [
        migrations.CreateModel(
            name='UserAction',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('username', models.CharField(max_length=100)),
                ('action', models.CharField(max_length=12, choices=[(b'disable', b'Disable'), (b'enable', b'Enable'), (b'comment', b'Comment'), (b'activate', b'Activate'), (b'deactivate', b'Deactivate'), (b'create', b'Create'), (b'delete', b'Delete'), (b'modify', b'Modify')])),
                ('options', models.CharField(default=None, max_length=1000, blank=True)),
                ('description', models.CharField(max_length=500, null=True)),
                ('comment', models.TextField(null=True, blank=True)),
                ('date', models.DateTimeField(default=django.utils.timezone.now, verbose_name=b'event date')),
                ('object_id', models.PositiveIntegerField()),
                ('content_type', models.ForeignKey(on_delete=django.db.models.deletion.SET_NULL, to='contenttypes.ContentType', null=True)),
                ('ruleset', models.ForeignKey(on_delete=django.db.models.deletion.SET_NULL, default=None, blank=True, to='rules.Ruleset', null=True)),
            ],
        ),
        migrations.AddField(
            model_name='rule',
            name='imported_date',
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name='rule',
            name='updated_date',
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
    ]
