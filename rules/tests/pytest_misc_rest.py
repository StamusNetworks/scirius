from django.urls import reverse
from rest_framework.test import APITestCase

from rules.models.misc import SystemSettings

from .test_misc import RestAPITestBase


class RestAPISystemSettingsTestCase(RestAPITestBase, APITestCase):
    def setUp(self):
        RestAPITestBase.setUp(self)
        APITestCase.setUp(self)

        self.system_settings = SystemSettings.objects.get_or_create(id=1)[0]

    def test_001_system_get(self):
        content = self.http_get(reverse("systemsettings"))
        self.assertEqual("custom_elasticsearch" in content, True)
        self.assertEqual("elasticsearch_url" in content, True)
        self.assertEqual("http_proxy" in content, True)
        self.assertEqual("use_http_proxy" in content, True)

    def test_002_system_settings_update(self):
        params = {
            "use_http_proxy": True,
            "http_proxy": "",
            "https_proxy": "",
            "custom_elasticsearch": False,
            "elasticsearch_url": "http://elasticsearch:9200/",
        }
        content = self.http_patch(reverse("systemsettings"), params)
        self.assertEqual(content["use_http_proxy"], True)

        params = {
            "use_http_proxy": False,
            "http_proxy": "",
            "https_proxy": "",
            "custom_elasticsearch": False,
            "elasticsearch_url": "http://elasticsearch:9200/",
        }
        content = self.http_put(reverse("systemsettings"), params)
        self.assertEqual(content["use_http_proxy"], False)
