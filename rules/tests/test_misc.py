from django.contrib.auth.models import User, Group
from rest_framework import status

from accounts.models import SciriusUser


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
