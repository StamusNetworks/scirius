import pytest
from io import BytesIO
from unittest.mock import patch

from django.http import HttpResponse
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from rules.api.source import UploadEditSourceTaskSerializer
from rules.models.model import (
    Ruleset,
    Source,
    UserAction,
)


ET_URL = "https://rules.emergingthreats.net/open/suricata-5.0/emerging.rules.tar.gz"

RULE_CONTENT = 'alert ip any any -> any any (msg:"Unicode test rule éàç"; content:"uid=0|28|root|29|"; classtype:bad-unknown; sid:2100498; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)\n'  # ignore_utf8_check: 233 224 231


@pytest.fixture
def ruleset(db):
    ruleset = Ruleset.objects.create(
        name="test ruleset", descr="descr", created_date=timezone.now(), updated_date=timezone.now()
    )
    ruleset.save()
    return ruleset


def _create_custom_source(drf: APIClient, method, datatype, ruleset: Ruleset, **kwargs):
    params = {
        "name": "sonic test custom source",
        "comment": "MyCustomComment",
        "method": method,
        "datatype": datatype,
    }
    params.update(kwargs)
    resp = drf.post(reverse("source-list"), params)
    assert resp.status_code == status.HTTP_201_CREATED
    sources = Source.objects.filter(name="sonic test custom source")
    assert sources.count() == 1

    source = sources.first()
    ruleset.sources.add(sources.first())
    return (source, ruleset)


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

    resp = drf.post(reverse("source-update-source", args=(source.pk,)))
    assert resp.status_code == status.HTTP_400_BAD_REQUEST

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


def test_003_custom_source_bad_upload(drf: APIClient, ruleset: Ruleset):
    source, _ruleset = _create_custom_source(drf, "local", "sigs", ruleset)

    with (
        open("/usr/bin/find", "rb") as f,
        patch.object(
            UploadEditSourceTaskSerializer,
            "spawn",
            return_value=HttpResponse('{"status": "OK", "code": 200, "message": null, "data": {"task_pk": 123}'),
        ),
        pytest.raises(OSError, match="Invalid tar file"),
    ):
        resp = drf.post(reverse("source-upload", args=(source.pk,)), {"file": f}, format="multipart")
        assert resp.status_code == status.HTTP_200_OK
        source.new_uploaded_file(f)

    resp = drf.delete(reverse("source-detail", args=(source.pk,)))
    assert resp.status_code == status.HTTP_204_NO_CONTENT
    sources = Source.objects.filter(pk=source.pk)
    assert sources.count() == 0


@pytest.mark.timeout(300)
@pytest.mark.slow
def test_004_custom_source_http(drf: APIClient, ruleset: Ruleset):
    source, _ruleset = _create_custom_source(drf, "http", "sigs", ruleset, uri=ET_URL, cert_verif=True)
    source.update()


def test_005_custom_source_bad_http(drf: APIClient, ruleset: Ruleset):
    source, _ruleset = _create_custom_source(drf, "http", "sigs", ruleset, uri="http://0.0.0.0:1234/")

    with pytest.raises(OSError, match="Connection refused"):
        source.update()


def test_006_custom_source_delete(drf: APIClient, ruleset: Ruleset):
    source, _ruleset = _create_custom_source(drf, "local", "sig", ruleset)
    resp = drf.delete(
        reverse("source-detail", args=(source.pk,)),
        {"comment": "source delete"},
    )
    assert resp.status_code == status.HTTP_204_NO_CONTENT

    ua = UserAction.objects.order_by("pk").last()
    assert ua.action_type == "delete_source"
    assert ua.comment == "source delete"
