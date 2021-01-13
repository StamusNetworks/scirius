from django.core.management.base import BaseCommand
from django.contrib.auth.models import Permission, Group as DjangoGroup
from django.contrib.contenttypes.models import ContentType

from accounts.models import SciriusUser, User, Group
from rules.models import FakePermissionModel


PERMS = [
    {'name': 'Configuration Auth', 'codename': 'configuration_auth'},
    {'name': 'Configuration Edit', 'codename': 'configuration_edit'},
    {'name': 'Configuration View', 'codename': 'configuration_view'},
    {'name': 'Events Edit', 'codename': 'events_edit'},
    {'name': 'Events Evebox', 'codename': 'events_evebox'},
    {'name': 'Events Kibana', 'codename': 'events_kibana'},
    {'name': 'Events Ryod', 'codename': 'events_ryod'},
    {'name': 'Events View', 'codename': 'events_view'},
    {'name': 'Ruleset Policy_Edit', 'codename': 'ruleset_policy_edit'},
    {'name': 'Ruleset Policy_View', 'codename': 'ruleset_policy_view'},
    {'name': 'Ruleset Update_Push', 'codename': 'ruleset_update_push'},
    {'name': 'Source Edit', 'codename': 'source_edit'},
    {'name': 'Source View', 'codename': 'source_view'}
]


class Command(BaseCommand):
    help = 'Create or restore scirius user in Superuser role with all permissions'

    def handle(self, *args, **options):
        dj_group, _ = DjangoGroup.objects.get_or_create(name='Superuser')
        role, _ = Group.objects.get_or_create(group=dj_group)
        user, user_created = User.objects.get_or_create(username='scirius')
        SciriusUser.objects.get_or_create(user=user, defaults={'timezone': 'UTC'})

        content_type = ContentType.objects.get_for_model(FakePermissionModel)

        if user_created:
            user.set_password('scirius')
            user.is_active = True
            user.save()

        if user not in dj_group.user_set.all():
            dj_group.user_set.add(user)

        for perm_dict in PERMS:
            perm, _ = Permission.objects.get_or_create(
                codename=perm_dict['codename'],
                name=perm_dict['name'],
                content_type=content_type
            )

            if perm not in dj_group.permissions.all():
                dj_group.permissions.add(perm)
