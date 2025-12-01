from django.db import migrations, models


def default_links(apps, schema_editor):
    Deeplink = apps.get_model('rules', 'Deeplink')
    Entity = apps.get_model('rules', 'DeepLinkEntity')

    # create entities first
    Entity.objects.bulk_create([
        Entity(name="PORT"),
        Entity(name="IP"),
        Entity(name="DOMAIN"),
        Entity(name="FILE_HASH"),
        Entity(name="CIPHER"),
        Entity(name="ASNUMBER"),
        Entity(name="MACADDRESS"),
        Entity(name="SHA256"),
        Entity(name="ASSET"),
        Entity(name="MITRE_TECHNIQUE_NAME"),
        Entity(name="MITRE_TECHNIQUE_ID"),
        Entity(name="MITRE_TACTIC_NAME"),
        Entity(name="MITRE_TACTIC_ID"),
        Entity(name="USERNAME"),
        Entity(name="HOSTNAME"),
        Entity(name="EMAIL"),
        Entity(name="ROLE"),
        Entity(name="NETWORK_INFO"),
        Entity(name="SIGNATURE"),
        Entity(name="PROTO"),
        Entity(name="APP_PROTO"),
        Entity(name="USER_AGENT"),
        Entity(name="COMMUNITY_ID"),
    ], ignore_conflicts=True)
    entities: dict[str, Entity] = {ent.name: ent for ent in Entity.objects.all()}

    link = Deeplink.objects.create(user_defined=False, enabled=True, name="DShield", template="https://www.dshield.org/data/port/{{ value }}")
    link.entities.add(entities["PORT"])
    link.save()

    link = Deeplink.objects.create(user_defined=False, enabled=True, name="VirusTotal", template="https://www.virustotal.com/gui/search/{{ value }}")
    link.entities.add(entities["FILE_HASH"])
    link.entities.add(entities["SHA256"])
    link.entities.add(entities["IP"])
    link.entities.add(entities["DOMAIN"])
    link.save()

    link = Deeplink.objects.create(user_defined=False, enabled=True, name="WhoIs", template="https://who.is/whois/{{ value }}")
    link.entities.add(entities["DOMAIN"])
    link.save()

    link = Deeplink.objects.create(user_defined=False, enabled=True, name="CipherSuite Info", template="https://ciphersuite.info/cs/{{ value }}/")
    link.entities.add(entities["CIPHER"])
    link.save()

    link = Deeplink.objects.create(user_defined=False, enabled=True, name="AS Number Info", template="https://bgpview.io/asn/{{ value }}")
    link.entities.add(entities["ASNUMBER"])
    link.save()

    link = Deeplink.objects.create(user_defined=False, enabled=True, name="Shodan", template="https://www.shodan.io/host/{{ value }}")
    link.entities.add(entities["IP"])
    link.save()

    link = Deeplink.objects.create(user_defined=False, enabled=True, name="Abuse CH", template="https://bazaar.abuse.ch/browse.php?search=sha256%3{{ value }}")
    link.entities.add(entities["SHA256"])
    link.save()

    link = Deeplink.objects.create(user_defined=False, enabled=True, name="MAC Address", template="https://maclookup.app/search/result?mac={{ value }}")
    link.entities.add(entities["MACADDRESS"])
    link.save()

    Deeplink.objects.bulk_create([
        Deeplink(user_defined=False, enabled=True, name="Google", template="https://www.google.com/search?q={{ value }}", all=True),
        Deeplink(user_defined=False, enabled=True, name="DuckDuckGo", template="https://duckduckgo.com/?q={{ value }}", all=True),
    ])


class Migration(migrations.Migration):

    dependencies = [
        ('rules', '0113_alter_source_ioc_type'),
    ]

    operations = [
        migrations.AddField(
            model_name='deeplink',
            name='user_defined',
            field=models.BooleanField(default=True, null=False),
        ),
        migrations.AddField(
            model_name='deeplink',
            name='enabled',
            field=models.BooleanField(default=True, null=False),
        ),
        migrations.AlterUniqueTogether(
            name='deeplink',
            unique_together={('name', 'template', 'user_defined')},
        ),

        migrations.RunPython(default_links),
    ]
