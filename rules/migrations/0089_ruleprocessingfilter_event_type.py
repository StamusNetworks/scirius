# Generated by Django 2.2.24 on 2021-08-04 07:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rules', '0088_ruleprocessingfilter_import_member'),
    ]

    operations = [
        migrations.AddField(
            model_name='ruleprocessingfilter',
            name='event_type',
            field=models.CharField(default='alert', max_length=32),
        ),
    ]
