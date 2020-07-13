# -*- coding: utf-8 -*-


from django.db import models, migrations
import suricata.models


class Migration(migrations.Migration):

    dependencies = [
        ('rules', '0041_source_authkey'),
    ]

    operations = [
        migrations.CreateModel(
            name='Suricata',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(unique=True, max_length=100, validators=[suricata.models.validate_hostname])),
                ('descr', models.CharField(max_length=400)),
                ('output_directory', models.CharField(max_length=400)),
                ('created_date', models.DateTimeField(verbose_name=b'date created')),
                ('updated_date', models.DateTimeField(verbose_name=b'date updated', blank=True)),
                ('ruleset', models.ForeignKey(blank=True, to='rules.Ruleset', null=True)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
    ]
