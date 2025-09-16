from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from .test_misc import RestAPITestBase


class RestAPIDeeplinkTestCase(RestAPITestBase, APITestCase):
    # Deeplinks and entites are setup during migrations
    def test_01_get_entities(self):
        links = self.http_get(reverse("deeplink-list"))
        self.assertTrue(links["count"] > 0)

        # get first deeplink
        ent_pk = links["results"][0]["pk"]
        link = self.http_get(reverse("deeplink-detail", args=(ent_pk,)))
        self.assertFalse(link["user_defined"])
        self.assertDictEqual(links["results"][0], link)

    def test_02_create_user_defined_deeplink(self):
        data = {
            "name": "Test",
            "template": "https://test.again/{{ value }}",
            "all": False,
            "entities": [{"name": "IP"}],
        }
        link = self.http_post(reverse("deeplink-list"), data, status=status.HTTP_201_CREATED)
        self.assertTrue(link["enabled"])
        self.assertTrue(link["user_defined"])

        # user_defined is in readonly with a default value
        data["name"] = "FakeNotUserDefined"
        data["user_defined"] = False
        link = self.http_post(reverse("deeplink-list"), data, status=status.HTTP_400_BAD_REQUEST)
        # self.assertTrue(link["user_defined"])

        # bad case: create a link with a bad entity
        data["name"] = "BadEntity"
        data["user_defined"] = True
        data["entities"] = [{"name": "IP"}, {"name": "BAD"}]
        self.http_post(reverse("deeplink-list"), data, status=status.HTTP_400_BAD_REQUEST)

    def test_03_edit_deeplink(self):
        # only enabled can be edited when user_defined=True
        data = {
            "name": "NewTest",
            "template": "https://test.again/{{ value }}",
            "all": False,
            "entities": [{"name": "IP"}],
        }
        link = self.http_post(reverse("deeplink-list"), data, status=status.HTTP_201_CREATED)
        pk = link["pk"]

        link = self.http_patch(
            reverse("deeplink-detail", args=(pk,)),
            {
                "name": "Renamed",
                "entities": [{"name": "IP"}, {"name": "DOMAIN"}],
                "enabled": False,
            },
            status=status.HTTP_200_OK,
        )
        self.assertEqual(link["name"], "Renamed")
        self.assertListEqual(link["entities"], [{"name": "IP"}, {"name": "DOMAIN"}])
        self.assertFalse(link["enabled"])

        # disable a stamus deeplink
        links = self.http_get(reverse("deeplink-list"), query=[("user_defined", "false")])
        original = links["results"][0]
        pk = original["pk"]
        self.http_patch(
            reverse("deeplink-detail", args=(pk,)),
            {"name": "Renamed", "entities": [{"name": "IP"}, {"name": "DOMAIN"}]},
            status=status.HTTP_400_BAD_REQUEST,
        )
        self.http_patch(
            reverse("deeplink-detail", args=(pk,)),
            {"enabled": True, "name": "Renamed", "entities": [{"name": "IP"}, {"name": "DOMAIN"}]},
            status=status.HTTP_400_BAD_REQUEST,
        )
        link = self.http_patch(reverse("deeplink-detail", args=(pk,)), {"enabled": False}, status=status.HTTP_200_OK)
        self.assertFalse(link["enabled"])

    def test_04_delete_deeplink(self):
        # only user defined deeplink can be deleted
        data = {
            "name": "DeleteTest",
            "template": "https://test.again/{{ value }}",
            "all": False,
            "entities": [{"name": "IP"}],
        }
        link = self.http_post(reverse("deeplink-list"), data, status=status.HTTP_201_CREATED)
        pk = link["pk"]
        self.http_delete(reverse("deeplink-detail", args=(pk,)), status=status.HTTP_204_NO_CONTENT)

        # try to delete a Stamus deeplink
        links = self.http_get(reverse("deeplink-list"), query=[("user_defined", "Ffalse")])
        pk = links["results"][0]["pk"]
        self.http_delete(reverse("deeplink-detail", args=(pk,)), status=status.HTTP_400_BAD_REQUEST)
