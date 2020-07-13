# -*- coding: utf-8 -*-


from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('suricata', '0003_suricata_yaml_file'),
    ]

    operations = [
        migrations.AlterField(
            model_name='suricata',
            name='output_directory',
            field=models.CharField(max_length=400, verbose_name=b'Rules directory'),
        ),
        migrations.AlterField(
            model_name='suricata',
            name='yaml_file',
            field=models.CharField(max_length=400, verbose_name=b'Suricata configuration file'),
        ),
    ]
