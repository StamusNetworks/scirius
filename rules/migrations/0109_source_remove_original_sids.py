# Generated by Django 3.2.25 on 2024-10-31 10:16

from django.db import migrations, models


def migrate(apps, schema_editor):
    # Models
    Source = apps.get_model('rules', 'Source')

    src = Source.objects.filter(datatype='threat').first()
    if src:
        src.remove_original_sids = False
        src.save()


class Migration(migrations.Migration):

    dependencies = [
        ('rules', '0108_alter_source_created_date'),
    ]

    operations = [
        migrations.AddField(
            model_name='source',
            name='remove_original_sids',
            field=models.BooleanField(default=True),
        ),
        migrations.RunPython(migrate),
    ]
