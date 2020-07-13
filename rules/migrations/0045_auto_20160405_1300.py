# -*- coding: utf-8 -*-


from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rules', '0044_flowbit_type'),
    ]

    operations = [
        migrations.AlterField(
            model_name='threshold',
            name='threshold_type',
            field=models.CharField(default=b'suppress', max_length=20, choices=[(b'threshold', b'threshold'), (b'suppress', b'suppress')]),
        ),
    ]
