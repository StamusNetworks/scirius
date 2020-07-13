# -*- coding: utf-8 -*-


from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rules', '0045_auto_20160405_1300'),
    ]

    operations = [
        migrations.AddField(
            model_name='source',
            name='cert_verif',
            field=models.BooleanField(default=True, verbose_name=b'Check certificates'),
        ),
    ]
