import pytest
from io import BytesIO
from unittest.mock import patch

from django.http import HttpResponse
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient, APITestCase

from rules.api.source import UploadEditSourceTaskSerializer
from rules.models.model import (
    Ruleset,
    Source,
    UserAction,
)

from .test_misc import RestAPITestBase


ET_URL = "https://rules.emergingthreats.net/open/suricata-5.0/emerging.rules.tar.gz"

RULE_CONTENT = 'alert ip any any -> any any (msg:"Unicode test rule éàç"; content:"uid=0|28|root|29|"; classtype:bad-unknown; sid:2100498; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)\n'  # ignore_utf8_check: 233 224 231


class RestAPIFileSourceTestCase(RestAPITestBase, APITestCase):
    def setUp(self):
        RestAPITestBase.setUp(self)
        APITestCase.setUp(self)

        self.ruleset = Ruleset.objects.create(
            name="test ruleset", descr="descr", created_date=timezone.now(), updated_date=timezone.now()
        )
        self.ruleset.save()

    def _create_custom_source(self, method, datatype, **kwargs):
        params = {
            "name": "sonic test custom source",
            "comment": "MyCustomComment",
            "method": method,
            "datatype": datatype,
        }
        params.update(kwargs)
        self.http_post(reverse("source-list"), params, status=status.HTTP_201_CREATED)
        sources = Source.objects.filter(name="sonic test custom source")
        self.assertEqual(sources.count() == 1, True)

        self.source = sources.first()
        self.ruleset.sources.add(sources.first())

    def _set_source_from_name(self, name):
        sources = Source.objects.filter(name=name)
        self.assertEqual(sources.count(), 1)
        self.source = sources[0]

    def test_003_custom_source_bad_upload(self):
        self._create_custom_source("local", "sigs")

        with (
            open("/usr/bin/find", "rb") as f,
            patch.object(
                UploadEditSourceTaskSerializer,
                "spawn",
                return_value=HttpResponse('{"status": "OK", "code": 200, "message": null, "data": {"task_pk": 123}'),
            ),
        ):
            self.http_post(reverse("source-upload", args=(self.source.pk,)), {"file": f}, format="multipart")
            try:
                self.source.new_uploaded_file(f)
            except Exception as e:
                self.assertTrue("Invalid tar file" in str(e))

        self.http_delete(reverse("source-detail", args=(self.source.pk,)), status=status.HTTP_204_NO_CONTENT)
        sources = Source.objects.filter(pk=self.source.pk)
        self.assertEqual(sources.count(), 0)

    @pytest.mark.timeout(300)
    @pytest.mark.slow
    def test_004_custom_source_http(self):
        self._create_custom_source("http", "sigs", uri=ET_URL, cert_verif=True)
        self.source.update()

    def test_005_custom_source_bad_http(self):
        self._create_custom_source("http", "sigs", uri="http://0.0.0.0:1234/")

        try:
            self.source.update()
        except OSError as e:
            self.assertTrue("Connection refused" in str(e))

    def test_006_custom_source_delete(self):
        self._create_custom_source("local", "sig")
        self.http_delete(
            reverse("source-detail", args=(self.source.pk,)),
            {"comment": "source delete"},
            status=status.HTTP_204_NO_CONTENT,
        )

        ua = UserAction.objects.order_by("pk").last()
        self.assertEqual(ua.action_type, "delete_source")
        self.assertEqual(ua.comment, "source delete")


def test_002_custom_source_upload(db, drf: APIClient):
    ruleset = Ruleset.objects.create(
        name="test ruleset", descr="descr", created_date=timezone.now(), updated_date=timezone.now()
    )

    # create custom source
    params = {
        "name": "sonic test custom source",
        "comment": "MyCustomComment",
        "method": "local",
        "datatype": "sig",
    }
    resp = drf.post(reverse("source-list"), params)
    assert resp.status_code == status.HTTP_201_CREATED
    sources = Source.objects.filter(name="sonic test custom source")
    assert sources.count() == 1

    source = sources.first()
    ruleset.sources.add(sources.first())

    source.new_uploaded_file(BytesIO(RULE_CONTENT.encode("utf-8")))

    resp = drf.post(reverse("source-update-source", args=(source.pk,)), status=status.HTTP_400_BAD_REQUEST)

    resp = drf.get(reverse("category-list") + f"?source={source.pk}")
    assert resp.status_code == status.HTTP_200_OK
    categories = resp.json().get("results", [])
    assert len(categories) == 1

    resp = drf.get(reverse("rule-list") + "?category={}".format(categories[0]["pk"]))
    assert resp.status_code == status.HTTP_200_OK
    rules = resp.json().get("results", [])
    assert len(rules) == 1

    rule = rules[0]

    expected = {
        "sid": 2100498,
        "msg": "Unicode test rule éàç",  # ignore_utf8_check: 233 224 231
    }
    assert rule == rule | expected

    expected = {"state": True, "commented_in_source": False, "content": RULE_CONTENT, "rev": 7}
    assert rule["versions"][0] == rule["versions"][0] | expected
