from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rules', '0116_ruleprocessingfilter_created_date'),
    ]

    operations = [
        migrations.AddIndex(
            model_name="categorytransformation",
            index=models.Index(
                fields=["ruleset", "category_transformation", "key", "value"],
                name="ct_rk_key_value_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="ruletransformation",
            index=models.Index(
                fields=["ruleset", "rule_transformation", "key", "value"],
                name="rt_rk_key_value_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="rulesettransformation",
            index=models.Index(
                fields=["ruleset_transformation", "key", "value"],
                name="rst_rk_key_value_idx",
            ),
        ),
    ]
