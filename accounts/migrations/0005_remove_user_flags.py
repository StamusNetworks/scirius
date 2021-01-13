from django.db import migrations


def migration(apps, _):
    User = apps.get_model('auth', 'User')
    User.objects.all().update(
        is_staff=False,
        is_superuser=False
    )


class Migration(migrations.Migration):
    dependencies = [
        ('rules', '0085_roles_migrations'),
        ('accounts', '0004_group'),
    ]

    operations = [
        migrations.RunPython(migration)
    ]
