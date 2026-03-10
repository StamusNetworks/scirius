import sys
import orjson
import re
from django.contrib.auth.models import User, Group
from django.urls import reverse
from django.test import TestCase
from django.utils import timezone
from django.http import HttpRequest
from django.db import models
from rest_framework import status, mixins
from rest_framework.test import APITestCase

from rules.rest_api import router
from accounts.models import SciriusUser

from rules.urls import urlpatterns
import inspect


class RestAPITestBase:
    def setUp(self):
        self.user = User.objects.create(username="scirius", password="scirius", is_superuser=False, is_staff=False)  # noqa: S106
        self.superuser_role = Group.objects.get(name="Superuser")
        self.staff_role = Group.objects.get(name="Staff")
        self.user_role = Group.objects.get(name="User")

        SciriusUser.objects.create(user=self.user, timezone="UTC")

        self.superuser_role.user_set.add(self.user)
        self.client.force_login(self.user)

    def _make_request(self, method: str, url: str, *args, **kwargs):
        func = getattr(self.client, method)
        http_status = kwargs.pop("status", status.HTTP_200_OK)

        if "format" not in kwargs:
            kwargs["format"] = "json"
        try:
            response = func(url, *args, **kwargs)
        except Exception as e:
            if len(e.args) >= 1:
                msg = f"Request failure on {url}:\n{e.args[0]}"
                e.args = (msg, *e.args[1:])
            raise

        # behavior/status could be different on remote and local build
        try:
            data_msg = str(getattr(response, "data", None))
        except UnicodeDecodeError:
            data_msg = repr(getattr(response, "data", None))
        msg = f"Request failed: \n{method.upper()} {url}\n{response.status_code} {response.reason_phrase}\n{data_msg}"

        if isinstance(http_status, tuple):
            self.assertEqual(response.status_code in http_status, True, msg)
            return getattr(response, "data", None), response.status_code
        self.assertEqual(response.status_code, http_status, msg)

        return getattr(response, "data", None)

    def http_get(self, *args, **kwargs):
        return self._make_request("get", *args, **kwargs)

    def http_post(self, *args, **kwargs):
        return self._make_request("post", *args, **kwargs)

    def http_put(self, *args, **kwargs):
        return self._make_request("put", *args, **kwargs)

    def http_patch(self, *args, **kwargs):
        return self._make_request("patch", *args, **kwargs)

    def http_delete(self, *args, **kwargs):
        return self._make_request("delete", *args, **kwargs)

    def http_options(self, *args, **kwargs):
        return self._make_request("options", *args, **kwargs)


class RestAPIListTestCase(RestAPITestBase, APITestCase):
    def setUp(self):
        RestAPITestBase.setUp(self)
        APITestCase.setUp(self)
        self.router = router

    def test_001_default_order(self):
        # Ordering must be set to prevent:
        # /usr/share/python/scirius-pro/local/lib/python2.7/site-packages/rest_framework/pagination.py:208: UnorderedObjectListWarning: Pagination may yield inconsistent results with an unordered object_list: <class 'rules.models.RuleTransformation'> QuerySet
        for _url, viewset, _view_name in self.router.registry:
            # Need to instanciate request and user because of FilterSetViewSet::get_queryset override that uses self.request.user
            v = viewset()
            v.request = HttpRequest()
            v.request.user = self.user

            if (
                v.get_queryset().ordered or not issubclass(viewset, mixins.ListModelMixin) or not getattr(v, "ordering_test", True)
            ):
                continue
            ERR = f'Viewset "{viewset.__name__}" must set an "ordering" attribute or have an ordered queryset'
            self.assertTrue(hasattr(viewset, "ordering"), ERR)
            self.assertNotEqual(len(viewset.ordering), 0, ERR)

    def test_002_list(self):
        for url, viewset, view_name in self.router.registry:
            if issubclass(viewset, mixins.ListModelMixin):
                url = reverse(view_name + "-list")
                if view_name.startswith("threat"):
                    url += "?event_view=false"
                self.http_get(url)

    def test_003_list_order(self):
        for _url, viewset, view_name in self.router.registry:
            if not hasattr(viewset, "ordering_fields"):
                continue
            for field in viewset.ordering_fields:
                self.http_get(reverse(view_name + "-list") + f"?ordering={field}")

    def test_004_list_filter(self):
        for _url, viewset, view_name in self.router.registry:
            v = viewset()
            v.request = HttpRequest()
            v.request.user = None

            if not hasattr(viewset, "filterset_fields"):
                continue

            for field in viewset.filterset_fields:
                if "__" in field:
                    continue

                member = v.get_queryset().model._meta.get_field(field)
                if isinstance(member, models.ForeignKey | models.ManyToManyField):
                    continue

                param = "0"
                if isinstance(member, models.DateTimeField):
                    param = timezone.now().strftime("%s")
                elif member.choices is not None and len(member.choices) > 0:
                    param = member.choices[0][0]

                self.http_get(reverse(view_name + "-list") + f"?{field}={param}")

    def test_005_list_search(self):
        for url, viewset, view_name in self.router.registry:
            if not hasattr(viewset, "search_fields"):
                continue
            url = reverse(view_name + "-list") + "?search=0"
            if view_name.startswith("threat"):
                continue
            self.http_get(url)

    def test_006_documentation(self):
        for _url, viewset, view_name in self.router.registry:
            self.assertNotEqual(viewset.__doc__, None, f"Viewset {view_name} has no documentation")


class PermissionsTestCase(TestCase):
    def setUp(self):
        self.urls = urlpatterns
        self.blacklist = {
            "rules.views.misc": ("index", "elasticsearch", "info", "history"),
            "rules.views.task": ("status",),
            "rules.views.ruleset": ("edit_ruleset",),
        }

    def test_001_test_view_decorator(self):
        for url in self.urls:
            try:
                module = url.callback.__module__
                view_name = url.callback.__name__
            except AttributeError:
                # admin part with no callbacks
                continue

            if view_name in self.blacklist.get(module, {}):
                continue

            view = getattr(sys.modules[module], view_name)
            is_class = inspect.isclass(view)

            if not is_class:
                source = inspect.getsource(view)
                def_index = source.find("def ")

                found = False
                for match in re.finditer("@", source[:def_index]):
                    index = match.start()
                    if (
                        source[index:def_index]
                        .strip()
                        .startswith(("@permission_required", "@tasks_permission_required", "@check_report_perms"))
                    ):
                        found = True
                        break
            else:
                if hasattr(view, "check_permissions") and view.check_permissions.__module__ == module:
                    found = True

            self.assertTrue(found, f'Permission not found on "{view_name}"')
