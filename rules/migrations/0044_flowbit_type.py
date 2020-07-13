# -*- coding: utf-8 -*-


from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rules', '0043_threshold'),
    ]

    operations = [
        migrations.AddField(
            model_name='flowbit',
            name='type',
            field=models.CharField(default='flowbits', max_length=12, choices=[(b'flowbits', b'Flowbits'), (b'hostbits', b'Hostbits'), (b'xbits', b'Xbits')]),
            preserve_default=False,
        ),
    ]
