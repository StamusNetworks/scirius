"""
Copyright(C) 2018, Stamus Networks
Written by Nicolas Frisoni <nfrisoni@stamus-networks.com>

This file is part of Scirius.

Scirius is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Scirius is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Scirius.  If not, see <http://www.gnu.org/licenses/>.
"""

from typing import TypedDict
import pytest

from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework.authtoken.models import Token

from accounts.rest_api import router
from .models import SciriusTokenUser, SciriusUser
from rules.tests.test_misc import RestAPIListTestCase


class TestUsers(TypedDict):
    sciriususer_staff: SciriusUser
    sciriususer_active: SciriusUser
    sciriususer_super: SciriusUser
    tokenuser_parent: SciriusUser


@pytest.fixture
def accounts(db, default_profile, drf: APIClient):
    from scirius.utils import get_middleware_module

    # Create scirius user is_superuser
    sciriususer_super, _ = SciriusUser.objects.get_or_create(user=default_profile["user"], defaults={"timezone": "UTC"})
    get_middleware_module("common").update_scirius_user_class(default_profile["user"], {})

    # Create Scirius User is_staff
    params = {"username": "sonic_staff", "timezone": "UTC", "password": "69scirius69"}
    resp = drf.post(reverse("sciriususer-list"), params)
    assert resp.status_code == status.HTTP_201_CREATED

    sciriususer_staff = SciriusUser.objects.get(pk=resp.json()["pk"])
    default_profile["staff_role"].user_set.add(sciriususer_staff.user)
    assert sciriususer_staff is not None
    assert sciriususer_staff.user.username == "sonic_staff"

    # User tokens
    params = {"username": "tokenuser_parent", "timezone": "UTC", "password": "69scirius69"}
    resp = drf.post(reverse("sciriususer-list"), params)
    assert resp.status_code == status.HTTP_201_CREATED
    tokenuser_parent = SciriusUser.objects.get(pk=resp.json()["pk"])
    default_profile["superuser_role"].user_set.add(tokenuser_parent.user)
    assert tokenuser_parent is not None
    assert tokenuser_parent.user.username == "tokenuser_parent"

    Token.objects.get_or_create(user=User.objects.create(username="tokenuser_child", password="69scirius69"))  # noqa: S106
    tokenuser_child = SciriusTokenUser.objects.create(
        user=User.objects.filter(username="tokenuser_child").first(), parent=tokenuser_parent
    )
    default_profile["superuser_role"].user_set.add(tokenuser_child.user)
    tokenuser_parent.tokenusers.add(tokenuser_child)

    # Create scirius user is_active
    params = {"username": "sonic_active", "timezone": "UTC", "password": "69scirius69"}
    resp = drf.post(reverse("sciriususer-list"), params)
    assert resp.status_code == status.HTTP_201_CREATED

    sciriususer_active = SciriusUser.objects.get(pk=resp.json()["pk"])
    default_profile["user_role"].user_set.add(sciriususer_active.user)
    assert sciriususer_active.user.username == "sonic_active"

    # Connect by default with is_staff user
    # self.client.force_login(self.sciriususer_staff.user)
    return TestUsers(
        sciriususer_active=sciriususer_active,
        sciriususer_staff=sciriususer_staff,
        sciriususer_super=sciriususer_super,
        tokenuser_parent=tokenuser_parent,
    )


@pytest.fixture
def drfs(accounts: TestUsers):
    client = APIClient()
    client.force_authenticate(user=accounts["sciriususer_staff"].user)
    # client.credentials(HTTP_AUTHORIZATION=f"Token {accounts['sciriususer_staff'].user.auth_token}")
    return client


@pytest.fixture
def drfa(accounts: TestUsers):
    client = APIClient()
    client.force_authenticate(user=accounts["sciriususer_active"].user)
    # client.credentials(HTTP_AUTHORIZATION=f"Token {accounts['sciriususer_active'].user.auth_token}")
    return client


def test_001_update_user_staff_details_own(db, accounts: TestUsers, drfs: APIClient):
    params = {"timezone": "UTC", "first_name": "toto", "last_name": "tutu", "email": "toto@tutu.fr"}
    resp = drfs.put(reverse("sciriususer-detail", args=(accounts["sciriususer_staff"].pk,)), params)
    assert resp.status_code == status.HTTP_200_OK

    # update its own details
    sciriususer_staff = SciriusUser.objects.get(pk=accounts["sciriususer_staff"].pk)
    assert sciriususer_staff.user.first_name == "toto"
    assert sciriususer_staff.user.last_name == "tutu"
    assert sciriususer_staff.user.email == "toto@tutu.fr"
    assert sciriususer_staff.timezone == "UTC"


def test_002_fail_update_user_staff_details_with_user_active(db, accounts: TestUsers, drfa: APIClient):
    # Update staff user with active user => forbidden
    params = {"username": "sonic_test_forbid", "timezone": "UTC"}
    assert (
        drfa.put(reverse("sciriususer-detail", args=(accounts["sciriususer_staff"].pk,)), params).status_code
        == status.HTTP_403_FORBIDDEN
    )


def test_003_update_user_staff_details_with_user_super(db, accounts: TestUsers, drf: APIClient):
    # Super user can update another user details
    params = {"username": "sonic_test_allow", "timezone": "UTC"}
    resp = drf.put(reverse("sciriususer-detail", args=(accounts["sciriususer_staff"].pk,)), params)
    assert resp.status_code == status.HTTP_200_OK

    sciriususer_staff = SciriusUser.objects.get(pk=resp.json()["pk"])
    assert sciriususer_staff.user.username == "sonic_test_allow"
    assert sciriususer_staff.timezone == "UTC"


def test_004_fail_update_user_active_details_own(db, accounts: TestUsers, drfa: APIClient):
    params = {"username": "sonic_test_done", "timezone": "Europe/Paris"}
    assert (
        drfa.put(reverse("sciriususer-detail", args=(accounts["sciriususer_active"].pk,)), params).status_code
        == status.HTTP_400_BAD_REQUEST
    )

    # update its own details
    sciriususer_active = SciriusUser.objects.get(pk=accounts["sciriususer_active"].pk)
    assert sciriususer_active is not None
    assert sciriususer_active.user.username == "sonic_active"
    assert sciriususer_active.timezone == "UTC"


def test_005_fail_update_user_active_details_with_user_staff(db, accounts: TestUsers, drfs: APIClient):
    params = {"username": "sonic_test_done", "timezone": "Europe/Paris"}
    assert (
        drfs.put(reverse("sciriususer-detail", args=(accounts["sciriususer_staff"].pk,)), params).status_code
        == status.HTTP_400_BAD_REQUEST
    )

    # update its own details
    sciriususer_staff = SciriusUser.objects.get(pk=accounts["sciriususer_staff"].pk)
    assert sciriususer_staff is not None
    assert sciriususer_staff.user.username != "sonic_test_done"
    assert sciriususer_staff.timezone != "Europe/Paris"


def test_006_update_user_active_details_with_user_super(db, accounts: TestUsers, drf: APIClient):
    # Super user can update another user details
    params = {"username": "sonic_test_allow", "timezone": "UTC"}
    resp = drf.put(reverse("sciriususer-detail", args=(accounts["sciriususer_active"].pk,)), params)
    assert resp.status_code == status.HTTP_200_OK

    sciriususer_staff = SciriusUser.objects.get(pk=resp.json()["pk"])
    assert sciriususer_staff.user.username == "sonic_test_allow"
    assert sciriususer_staff.timezone == "UTC"


def test_007_fail_upgrade_privilege_from_active_to_staff(db, accounts: TestUsers, default_profile, drfa: APIClient):
    params = {"role": default_profile["staff_role"].pk}
    assert (
        drfa.put(reverse("sciriususer-detail", args=(accounts["sciriususer_active"].pk,)), params).status_code
        == status.HTTP_400_BAD_REQUEST
    )


def test_008_fail_upgrade_privilege_from_active_to_super(db, accounts: TestUsers, default_profile, drfa: APIClient):
    params = {"role": default_profile["superuser_role"].pk}
    assert (
        drfa.put(reverse("sciriususer-detail", args=(accounts["sciriususer_active"].pk,)), params).status_code
        == status.HTTP_400_BAD_REQUEST
    )


def test_009_fail_upgrade_privilege_from_staff_to_super(db, accounts: TestUsers, default_profile, drfs: APIClient):
    params = {"role": default_profile["superuser_role"].pk}
    assert (
        drfs.put(reverse("sciriususer-detail", args=(accounts["sciriususer_staff"].pk,)), params).status_code
        == status.HTTP_400_BAD_REQUEST
    )


def test_010_fail_update_user_active_password_from_details_api_with_user_super(db, accounts: TestUsers, drf: APIClient):
    params = {"username": "sonic_active_updated", "password": "51other51"}
    assert (
        drf.put(reverse("sciriususer-detail", args=(accounts["sciriususer_active"].pk,)), params).status_code
        == status.HTTP_403_FORBIDDEN
    )


def test_011_fail_update_user_staff_password_from_details_api_with_user_super(db, accounts: TestUsers, drf: APIClient):
    params = {"username": "sonic_staff_updated", "password": "51other51"}
    assert (
        drf.put(reverse("sciriususer-detail", args=(accounts["sciriususer_staff"].pk,)), params).status_code
        == status.HTTP_403_FORBIDDEN
    )


def test_012_fail_update_user_super_password_from_details_api_with_user_super(db, accounts: TestUsers, drf: APIClient):
    params = {"username": "sonic_super_updated", "password": "51other51"}
    assert (
        drf.put(reverse("sciriususer-detail", args=(accounts["sciriususer_super"].pk,)), params).status_code
        == status.HTTP_403_FORBIDDEN
    )


# ################
# ###### Password
def test_020_fail_update_user_staff_password_own_with_missing_field(db, accounts: TestUsers, drfs: APIClient):
    # wrong request
    params = {"new_password": "51scirius51"}
    assert (
        drfs.post(reverse("sciriususer-password", args=(accounts["sciriususer_staff"].pk,)), params).status_code
        == status.HTTP_400_BAD_REQUEST
    )
    assert accounts["sciriususer_staff"].user.check_password("69scirius69")


def test_021_update_user_staff_password_own(db, accounts: TestUsers, drf: APIClient):
    # update its own password
    params = {"old_password": "69scirius69", "new_password": "51scirius51"}
    assert (
        drf.post(reverse("sciriususer-password", args=(accounts["sciriususer_staff"].pk,)), params).status_code
        == status.HTTP_200_OK
    )

    sciriususer = SciriusUser.objects.get(pk=accounts["sciriususer_staff"].pk)
    assert sciriususer.user.check_password("51scirius51")


def test_022_fail_update_user_active_password_with_user_staff(db, accounts: TestUsers, drfs: APIClient):
    # cannot update another user password (is_staff)

    params = {"new_password": "51sciriusro51", "old_password": "69sciriusro69"}
    assert (
        drfs.post(reverse("sciriususer-password", args=(accounts["sciriususer_active"].pk,)), params).status_code
        == status.HTTP_403_FORBIDDEN
    )


def test_023_fail_update_user_staff_password_with_user_active(db, accounts: TestUsers, drfa: APIClient):
    # cannot update another user password (is_active)

    params = {"new_password": "51scirius51", "old_password": "69scirius69"}
    assert (
        drfa.post(reverse("sciriususer-password", args=(accounts["sciriususer_staff"].pk,)), params).status_code
        == status.HTTP_403_FORBIDDEN
    )


def test_024_update_user_staff_password_with_user_super(db, accounts: TestUsers, drf: APIClient):
    # can update another user password (superuser)

    params = {"new_password": "51scirius51"}
    assert (
        drf.post(reverse("sciriususer-password", args=(accounts["sciriususer_staff"].pk,)), params).status_code
        == status.HTTP_200_OK
    )


# ################
# ###### Token
def test_030_create_user_staff_token_own(db, accounts: TestUsers, drf: APIClient):
    # generate a token
    resp = drf.post(reverse("sciriususer-token", args=(accounts["sciriususer_staff"].pk,)))
    assert resp.status_code == status.HTTP_200_OK
    response = resp.json()
    assert "token" in response

    # compare with generated token with db token
    token = response["token"]
    token_db = Token.objects.filter(user_id=accounts["sciriususer_staff"].user.pk)
    assert token, str(token_db[0])


def test_031_get_user_staff_token_own(db, accounts: TestUsers, drf: APIClient):
    # Need to create token before getting it
    test_030_create_user_staff_token_own(db, accounts, drf)

    resp = drf.get(reverse("sciriususer-token", args=(accounts["sciriususer_staff"].pk,)))
    assert resp.status_code == status.HTTP_200_OK
    response = resp.json()
    assert "token" in response

    token = response["token"]
    token_db = Token.objects.filter(user_id=accounts["sciriususer_staff"].user.pk)
    assert token, str(token_db[0])


def test_032_fail_get_user_staff_token_with_user_active(db, accounts: TestUsers, drfa: APIClient):
    assert (
        drfa.get(reverse("sciriususer-token", args=(accounts["sciriususer_staff"].pk,)), {}).status_code
        == status.HTTP_403_FORBIDDEN
    )


def test_033_fail_create_user_staff_token_with_user_active(db, accounts: TestUsers, drfa: APIClient):
    assert (
        drfa.post(reverse("sciriususer-token", args=(accounts["sciriususer_staff"].pk,)), {}).status_code
        == status.HTTP_403_FORBIDDEN
    )


def test_034_get_user_active_token_own(db, accounts: TestUsers, drfa: APIClient):
    assert (
        drfa.get(reverse("sciriususer-token", args=(accounts["sciriususer_active"].pk,)), {}).status_code
        == status.HTTP_200_OK
    )


def test_035_create_user_active_token_own(db, accounts: TestUsers, drfa: APIClient):
    assert (
        drfa.post(reverse("sciriususer-token", args=(accounts["sciriususer_active"].pk,)), {}).status_code
        == status.HTTP_200_OK
    )


# ################
# ###### List
def test_040_fail_list_all_users_with_user_active(db, accounts: TestUsers, drfa: APIClient):
    assert drfa.get(reverse("sciriususer-list")).status_code == status.HTTP_403_FORBIDDEN


def test_041_fail_list_all_users_with_user_staff(db, accounts: TestUsers, drfs: APIClient):
    assert drfs.get(reverse("sciriususer-list")).status_code == status.HTTP_403_FORBIDDEN


def test_042_list_all_users_with_user_super(db, accounts: TestUsers, drf: APIClient):
    assert drf.get(reverse("sciriususer-list")).status_code == status.HTTP_200_OK


def test_043_unique_user(db, accounts: TestUsers, drf: APIClient):
    resp = drf.post(reverse("sciriususer-list"), {"username": "default_scirius", "password": "scirius"})
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json() == {"username": ["This field must be unique."]}


def test_044_tokenuser_disabled(db, accounts: TestUsers):
    client = APIClient()
    user = accounts["tokenuser_parent"].tokenusers.first().user

    # Auth works
    assert user.is_active
    client.credentials(HTTP_AUTHORIZATION=f"Token {user.auth_token}")
    res = client.get(reverse("tokenuser-list"))
    # raise Exception(user.__dict__, res.status_code, user.auth_token, res.json())
    assert res.status_code == status.HTTP_200_OK

    # Auth forbidden
    accounts["tokenuser_parent"].user.is_active = False
    accounts["tokenuser_parent"].user.save()
    accounts["tokenuser_parent"].update_token_users()
    user.refresh_from_db()

    assert not user.is_active
    client.credentials(HTTP_AUTHORIZATION=f"Token {user.auth_token}")
    res = client.get(reverse("tokenuser-list"))
    assert res.status_code == status.HTTP_403_FORBIDDEN

    # Auth works
    accounts["tokenuser_parent"].user.is_active = True
    accounts["tokenuser_parent"].user.save()
    accounts["tokenuser_parent"].update_token_users()
    user.refresh_from_db()

    assert user.is_active
    client.credentials(HTTP_AUTHORIZATION=f"Token {user.auth_token}")
    res = client.get(reverse("tokenuser-list"))
    assert res.status_code == status.HTTP_200_OK


class RestAPIAccountListTestCase(RestAPIListTestCase):
    def setUp(self):
        super(RestAPIAccountListTestCase, self).setUp()
        self.router = router
