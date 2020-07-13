# -*- coding: utf-8 -*-


from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rules', '0053_unique_none_rules'),
    ]

    operations = [
        migrations.AlterField(
            model_name='useraction',
            name='action',
            field=models.CharField(max_length=12, choices=[(b'disable', b'Disable'), (b'enable', b'Enable'), (b'comment', b'Comment'), (b'activate', b'Activate'), (b'deactivate', b'Deactivate'), (b'create', b'Create'), (b'delete', b'Delete'), (b'modify', b'Modify'), (b'login', b'Login'), (b'logout', b'Logout')]),
        ),
        migrations.AlterField(
            model_name='useraction',
            name='object_id',
            field=models.PositiveIntegerField(null=True),
        ),
    ]
