# -*- coding: utf-8 -*-


from django.db import models, migrations
import datetime


class Migration(migrations.Migration):

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Category',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(max_length=100)),
                ('filename', models.CharField(max_length=200)),
                ('descr', models.CharField(max_length=400, blank=True)),
                ('created_date', models.DateTimeField(default=datetime.datetime(2014, 11, 9, 19, 55, 32, 204381), verbose_name=b'date created')),
            ],
            options={
                'verbose_name_plural': 'categories',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Rule',
            fields=[
                ('sid', models.IntegerField(serialize=False, primary_key=True)),
                ('msg', models.CharField(max_length=1000)),
                ('state', models.BooleanField(default=True)),
                ('rev', models.IntegerField(default=0)),
                ('content', models.CharField(max_length=10000)),
                ('category', models.ForeignKey(to='rules.Category')),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Ruleset',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(unique=True, max_length=100)),
                ('descr', models.CharField(max_length=400, blank=True)),
                ('created_date', models.DateTimeField(verbose_name=b'date created')),
                ('updated_date', models.DateTimeField(verbose_name=b'date updated', blank=True)),
                ('categories', models.ManyToManyField(to='rules.Category', blank=True)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Source',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(unique=True, max_length=100)),
                ('created_date', models.DateTimeField(verbose_name=b'date created')),
                ('updated_date', models.DateTimeField(null=True, verbose_name=b'date updated', blank=True)),
                ('method', models.CharField(max_length=10, choices=[(b'http', b'HTTP URL'), (b'local', b'Upload')])),
                ('datatype', models.CharField(max_length=10, choices=[(b'sigs', b'Signatures files in tar archive'), (b'sig', b'Individual Signatures file'), (b'other', b'Other content')])),
                ('uri', models.CharField(max_length=400, null=True, blank=True)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='SourceAtVersion',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('version', models.CharField(max_length=42)),
                ('git_version', models.CharField(default=b'HEAD', max_length=42)),
                ('updated_date', models.DateTimeField(default=datetime.datetime(2014, 11, 9, 19, 55, 32, 203594), verbose_name=b'date updated', blank=True)),
                ('source', models.ForeignKey(to='rules.Source')),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='SourceUpdate',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('created_date', models.DateTimeField(default=datetime.datetime(2014, 11, 9, 19, 55, 32, 204018), verbose_name=b'date of update', blank=True)),
                ('data', models.TextField()),
                ('version', models.CharField(max_length=42)),
                ('changed', models.IntegerField(default=0)),
                ('source', models.ForeignKey(to='rules.Source')),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.AddField(
            model_name='ruleset',
            name='sources',
            field=models.ManyToManyField(to='rules.SourceAtVersion'),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='ruleset',
            name='suppressed_rules',
            field=models.ManyToManyField(to='rules.Rule', blank=True),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='category',
            name='source',
            field=models.ForeignKey(to='rules.Source'),
            preserve_default=True,
        ),
    ]
