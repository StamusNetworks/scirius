from django.db import migrations

def migration(apps, _):
    ContentType = apps.get_model('contenttypes', 'ContentType')
    UserAction = apps.get_model('rules', 'UserAction')
    UserActionObject = apps.get_model('rules', 'UserActionObject')
    Ruleset = apps.get_model('rules', 'Ruleset')

    types = ('create_rule_filter', 'edit_rule_filter', 'delete_rule_filter')
    for ua in UserAction.objects.filter(action_type__in=types):
        content_type = ContentType.objects.get_for_model(Ruleset)
        ua_obj_params = {
            'action_key': 'ruleset',
            'action_value': 'Unknown',
            'user_action': ua,
            'content_type': content_type,
            'object_id': None
        }

        uao = UserActionObject(**ua_obj_params)
        uao.save()
        ua.save()


class Migration(migrations.Migration):
    dependencies = [
        ('rules', '0090_useraction_ip'),
    ]

    operations = [
        migrations.RunPython(migration),
    ]
