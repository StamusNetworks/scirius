from django.db import migrations


ROLES = {
    'Superuser': {
        'users_filter': {'is_superuser': True},
        'modules': {
            'configuration': {
                'permissions': {
                    'view': True,
                    'edit': True,
                    'auth': True,
                },
            },
            'source': {
                'permissions': {
                    'view': True,
                    'edit': True,
                }
            },
            'ruleset': {
                'permissions': {
                    'policy_view': True,
                    'policy_edit': True,
                    'update_push': True
                }
            },
            'events': {
                'permissions': {
                    'view': True,
                    'edit': True,
                    'kibana': True,
                    'evebox': True,
                },
            }
        }
    },
    'Staff': {
        'users_filter': {'is_staff': True, 'is_superuser': False},
        'modules': {
            'configuration': {
                'permissions': {
                    'view': True,
                    'edit': True,
                    'auth': False,
                },
            },
            'source': {
                'permissions': {
                    'view': True,
                    'edit': True,
                }
            },
            'ruleset': {
                'permissions': {
                    'policy_view': True,
                    'policy_edit': True,
                    'update_push': True
                }
            },
            'events': {
                'permissions': {
                    'view': True,
                    'edit': True,
                    'kibana': True,
                    'evebox': True,
                },
            }
        }
    },
    'User': {
        'users_filter': {'is_staff': False, 'is_superuser': False},
        'modules': {
            'configuration': {
                'permissions': {
                    'view': True,
                    'edit': False,
                    'auth': False,
                },
            },
            'source': {
                'permissions': {
                    'view': True,
                    'edit': False,
                }
            },
            'ruleset': {
                'permissions': {
                    'policy_view': True,
                    'policy_edit': False,
                    'update_push': False
                }
            },
            'events': {
                'permissions': {
                    'view': True,
                    'edit': False,
                    'kibana': True,
                    'evebox': True,
                },
            }
        }
    }
}


def migration(apps, _):
    User = apps.get_model('auth', 'User')
    Group = apps.get_model('accounts', 'Group')
    DjangoGroup = apps.get_model('auth', 'Group')
    Permission = apps.get_model('auth', 'Permission')
    ContentType = apps.get_model('contenttypes', 'ContentType')

    content_type = ContentType.objects.get_for_model(
        apps.get_model('rules', 'FakePermissionModel'),
    )

    for role, role_content in ROLES.items():
        dg_group, _ = DjangoGroup.objects.get_or_create(name=role)
        Group.objects.get_or_create(group=dg_group)
        users = User.objects.filter(**role_content['users_filter'])

        for module, mod_content in role_content['modules'].items():
            perms = mod_content['permissions']

            for perm_type, allowed in perms.items():
                if allowed:
                    permission, _ = Permission.objects.get_or_create(
                        codename='{}_{}'.format(module, perm_type),
                        name='{} {}'.format(module.title(), perm_type.title()),
                        content_type=content_type
                    )
                    dg_group.permissions.add(permission)

        # compatibility: add type of users in their corresponding role
        if users:
            for user in users:
                dg_group.user_set.add(user)


class Migration(migrations.Migration):
    dependencies = [
        ('rules', '0084_fakepermissionmodel'),
        ('accounts', '0004_group'),
    ]

    operations = [
        migrations.RunPython(migration),
    ]
