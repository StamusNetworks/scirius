# -*- coding: utf-8 -*-


from django.db import models, migrations
import datetime


class Migration(migrations.Migration):

    dependencies = [
        ('rules', '0008_auto_20141210_2057'),
    ]

    operations = [
        migrations.CreateModel(
            name='Flowbit',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(max_length=100)),
                ('set', models.BooleanField(default=False)),
                ('isset', models.BooleanField(default=False)),
                ('enable', models.BooleanField(default=True)),
                ('source', models.ForeignKey(to='rules.Source')),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.AddField(
            model_name='rule',
            name='flowbits',
            field=models.ManyToManyField(to='rules.Flowbit'),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='category',
            name='created_date',
            field=models.DateTimeField(default=datetime.datetime(2014, 12, 14, 12, 3, 27, 650438), verbose_name=b'date created'),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='sourceatversion',
            name='updated_date',
            field=models.DateTimeField(default=datetime.datetime(2014, 12, 14, 12, 3, 27, 649694), verbose_name=b'date updated', blank=True),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='sourceupdate',
            name='created_date',
            field=models.DateTimeField(default=datetime.datetime(2014, 12, 14, 12, 3, 27, 650025), verbose_name=b'date of update', blank=True),
            preserve_default=True,
        ),
    ]
