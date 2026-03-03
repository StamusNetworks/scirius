from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient


# Deeplinks and entites are setup during migrations
def test_01_get_entities(db, drf: APIClient):
    resp = drf.get(reverse("deeplink-list"))
    assert resp.status_code == status.HTTP_200_OK
    links = resp.json()
    assert links["count"] > 0

    # get first deeplink
    ent_pk = links["results"][0]["pk"]
    resp = drf.get(reverse("deeplink-detail", args=(ent_pk,)))
    assert resp.status_code == status.HTTP_200_OK
    link = resp.json()
    assert not link["user_defined"]
    assert links["results"][0] == link


def test_02_create_user_defined_deeplink(db, drf: APIClient):
    data = {
        "name": "Test",
        "template": "https://test.again/{{ value }}",
        "all": False,
        "entities": [{"name": "IP"}],
    }
    resp = drf.post(reverse("deeplink-list"), data)
    assert resp.status_code == status.HTTP_201_CREATED
    link = resp.json()
    assert link["enabled"]
    assert link["user_defined"]

    # user_defined is in readonly with a default value
    data["name"] = "FakeNotUserDefined"
    data["user_defined"] = False
    resp = drf.post(reverse("deeplink-list"), data)
    assert resp.status_code == status.HTTP_400_BAD_REQUEST

    # bad case: create a link with a bad entity
    data["name"] = "BadEntity"
    data["user_defined"] = True
    data["entities"] = [{"name": "IP"}, {"name": "BAD"}]
    resp = drf.post(reverse("deeplink-list"), data)
    assert resp.status_code == status.HTTP_400_BAD_REQUEST


def test_03_edit_deeplink(db, drf: APIClient):
    # only enabled can be edited when user_defined=True
    data = {
        "name": "NewTest",
        "template": "https://test.again/{{ value }}",
        "all": False,
        "entities": [{"name": "IP"}],
    }
    resp = drf.post(reverse("deeplink-list"), data)
    assert resp.status_code == status.HTTP_201_CREATED
    link = resp.json()
    pk = link["pk"]

    resp = drf.patch(
        reverse("deeplink-detail", args=(pk,)),
        {
            "name": "Renamed",
            "entities": [{"name": "IP"}, {"name": "DOMAIN"}],
            "enabled": False,
        },
    )
    assert resp.status_code == status.HTTP_200_OK
    link = resp.json()
    assert link["name"] == "Renamed"
    assert link["entities"] == [{"name": "IP"}, {"name": "DOMAIN"}]
    assert not link["enabled"]

    # disable a stamus deeplink
    resp = drf.get(reverse("deeplink-list"), query=[("user_defined", "false")])
    assert resp.status_code == status.HTTP_200_OK
    links = resp.json()
    original = links["results"][0]
    pk = original["pk"]
    assert drf.patch(
        reverse("deeplink-detail", args=(pk,)),
        {"name": "Renamed", "entities": [{"name": "IP"}, {"name": "DOMAIN"}]},
    ).status_code == status.HTTP_400_BAD_REQUEST
    assert drf.patch(
        reverse("deeplink-detail", args=(pk,)),
        {"enabled": True, "name": "Renamed", "entities": [{"name": "IP"}, {"name": "DOMAIN"}]},
    ).status_code == status.HTTP_400_BAD_REQUEST
    resp = drf.patch(reverse("deeplink-detail", args=(pk,)), {"enabled": False})
    assert resp.status_code == status.HTTP_200_OK
    link = resp.json()
    assert not link["enabled"]


def test_04_delete_deeplink(db, drf: APIClient):
    # only user defined deeplink can be deleted
    data = {
        "name": "DeleteTest",
        "template": "https://test.again/{{ value }}",
        "all": False,
        "entities": [{"name": "IP"}],
    }
    resp = drf.post(reverse("deeplink-list"), data)
    assert resp.status_code == status.HTTP_201_CREATED
    link = resp.json()
    pk = link["pk"]
    resp = drf.delete(reverse("deeplink-detail", args=(pk,)))
    assert resp.status_code == status.HTTP_204_NO_CONTENT

    # try to delete a Stamus deeplink
    resp = drf.get(reverse("deeplink-list"), query=[("user_defined", "False")])
    assert resp.status_code == status.HTTP_200_OK
    links = resp.json()
    pk = links["results"][0]["pk"]
    assert drf.delete(reverse("deeplink-detail", args=(pk,))).status_code == status.HTTP_400_BAD_REQUEST
