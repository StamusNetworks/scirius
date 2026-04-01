import orjson

from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient, APITestCase

from rules.models.model import (
    Ruleset,
    Source,
    SourceUpdate,
)

from .test_misc import RestAPITestBase


class RestAPIPublicSourceTestCase(RestAPITestBase, APITestCase):
    def setUp(self):
        RestAPITestBase.setUp(self)
        APITestCase.setUp(self)

        self.ruleset = Ruleset.objects.create(
            name="test ruleset", descr="descr", created_date=timezone.now(), updated_date=timezone.now()
        )
        self.ruleset.save()

    def _create_public_source(self):
        params = {
            "name": "sonic test public source",
            "comment": "MyPublicComment",
            "public_source": "oisf/trafficid",
        }
        self.http_post(reverse("publicsource-list"), params, status=status.HTTP_201_CREATED)
        sources = Source.objects.filter(name="sonic test public source")
        self.assertEqual(sources.count() == 1, True)

        self.public_source = sources.first()
        self.ruleset.sources.add(sources.first())

    def test_007_source_name_unicode(self):
        self._create_public_source()

        unic = 'é&"_è-àç'  # ignore_utf8_check: 233 232 231 224
        response = self.http_patch(reverse("publicsource-detail", args=(self.public_source.pk,)), {"name": unic})
        self.assertEqual(response["name"], unic)


def test_001_public_source(db, drf: APIClient):
    ruleset = Ruleset.objects.create(
        name="test ruleset", descr="descr", created_date=timezone.now(), updated_date=timezone.now()
    )

    # create public source using REST API
    params = {
        "name": "sonic test public source",
        "comment": "MyPublicComment",
        "public_source": "oisf/trafficid",
    }
    resp = drf.post(reverse("publicsource-list"), params)
    assert resp.status_code == status.HTTP_201_CREATED
    sources = Source.objects.filter(name="sonic test public source")
    assert sources.count() == 1

    public_source = sources.first()
    ruleset.sources.add(sources.first())

    resp = drf.get(reverse("publicsource-fetch-list-sources"))
    assert resp.status_code == status.HTTP_200_OK
    assert resp.json() == {"fetch": "ok"}

    public_source.update()

    # behavior/status could be different on remote and local build
    test_results = public_source.test()

    if test_results["status"] is True:
        drf.get(reverse("publicsource-list-sources"))
    else:
        assert "errors" in test_results

    resp = drf.delete(reverse("publicsource-detail", args=(public_source.pk,)))
    assert resp.status_code == status.HTTP_204_NO_CONTENT
    sources = Source.objects.filter(pk=public_source.pk)
    assert sources.count() == 0


def test_all_changelog(db, drf):
    # create a public source
    ruleset = Ruleset.objects.create(
        name="test ruleset", descr="descr", created_date=timezone.now(), updated_date=timezone.now()
    )
    ruleset.save()

    params = {
        "name": "sonic test public source",
        "comment": "MyPublicComment",
        "public_source": "oisf/trafficid",
    }
    resp = drf.post(reverse("publicsource-list"), params)
    resp.status_code == status.HTTP_201_CREATED
    sources = Source.objects.filter(name="sonic test public source")
    assert sources.count() == 1

    public_source = sources.first()
    ruleset.sources.add(sources.first())

    data = {
        "deleted": [],
        "updated": [
            {
                "msg": "SURICATA TRAFFIC-ID: Debian APT-GET",
                "category": "Suricata Traffic ID ruleset Sigs",
                "pk": 300000032,
                "sid": 300000032,
            },
            {
                "msg": "SURICATA TRAFFIC-ID: Ubuntu APT-GET",
                "category": "Suricata Traffic ID ruleset Sigs",
                "pk": 300000033,
                "sid": 300000033,
            },
        ],
        "added": [],
    }

    SourceUpdate.objects.create(
        source=public_source,
        created_date=timezone.now(),
        data=orjson.dumps(data).decode("utf-8"),
        changed=len(data["deleted"]) + len(data["added"]) + len(data["updated"]),
    )

    public_source.update()
    resp = drf.get(reverse("sourceupdate-list"))
    assert resp.status_code == status.HTTP_200_OK
    response = resp.json()
    assert response["results"][0]["source"] == public_source.pk
    assert response["results"][0]["data"]["updated"] == data["updated"]
