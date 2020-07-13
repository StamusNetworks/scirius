# -*- coding: utf-8 -*-


from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rules', '0048_custom_es'),
    ]

    operations = [
        migrations.AddField(
            model_name='ruleset',
            name='drop_categories',
            field=models.ManyToManyField(related_name='categories_drop', to='rules.Category', blank=True),
        ),
        migrations.AddField(
            model_name='ruleset',
            name='drop_rules',
            field=models.ManyToManyField(related_name='rules_drop', to='rules.Rule', blank=True),
        ),
        migrations.AddField(
            model_name='ruleset',
            name='filestore_categories',
            field=models.ManyToManyField(related_name='categories_filestore', to='rules.Category', blank=True),
        ),
        migrations.AddField(
            model_name='ruleset',
            name='filestore_rules',
            field=models.ManyToManyField(related_name='rules_filestore', to='rules.Rule', blank=True),
        ),
        migrations.AddField(
            model_name='ruleset',
            name='nodrop_rules',
            field=models.ManyToManyField(related_name='rules_nodrop', to='rules.Rule', blank=True),
        ),
        migrations.AddField(
            model_name='ruleset',
            name='nofilestore_rules',
            field=models.ManyToManyField(related_name='rules_nofilestore', to='rules.Rule', blank=True),
        ),
        migrations.AddField(
            model_name='ruleset',
            name='noreject_rules',
            field=models.ManyToManyField(related_name='rules_noreject', to='rules.Rule', blank=True),
        ),
        migrations.AddField(
            model_name='ruleset',
            name='reject_categories',
            field=models.ManyToManyField(related_name='categories_reject', to='rules.Category', blank=True),
        ),
        migrations.AddField(
            model_name='ruleset',
            name='reject_rules',
            field=models.ManyToManyField(related_name='rules_reject', to='rules.Rule', blank=True),
        ),
    ]
