# Generated by Django 2.2.17 on 2021-06-07 09:06

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rules', '0087_systemsettings_use_proxy_for_es'),
    ]

    operations = [
        migrations.AddField(
            model_name='filterset',
            name='imported',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='ruleprocessingfilter',
            name='imported',
            field=models.BooleanField(default=False),
        ),
    ]
