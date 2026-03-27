import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from rules.models.misc import SystemSettings


@pytest.fixture
def system_settings(db):
    return SystemSettings.objects.get_or_create(id=1)[0]


def test_001_system_get(drf: APIClient, system_settings):
    resp = drf.get(reverse("systemsettings"))
    assert resp.status_code == status.HTTP_200_OK
    content = resp.json()
    assert "custom_elasticsearch" in content
    assert "elasticsearch_url" in content
    assert "http_proxy" in content
    assert "use_http_proxy" in content


def test_002_system_settings_update(drf: APIClient, system_settings):
    params = {
        "use_http_proxy": True,
        "http_proxy": "",
        "https_proxy": "",
        "custom_elasticsearch": False,
        "elasticsearch_url": "http://elasticsearch:9200/",
    }
    resp = drf.patch(reverse("systemsettings"), params)
    assert resp.status_code == status.HTTP_200_OK
    assert resp.json()["use_http_proxy"]

    params = {
        "use_http_proxy": False,
        "http_proxy": "",
        "https_proxy": "",
        "custom_elasticsearch": False,
        "elasticsearch_url": "http://elasticsearch:9200/",
    }
    resp = drf.put(reverse("systemsettings"), params)
    assert resp.status_code == status.HTTP_200_OK
    assert not resp.json()["use_http_proxy"]
