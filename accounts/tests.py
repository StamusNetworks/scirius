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


from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework.authtoken.models import Token

from accounts.rest_api import router
from .models import SciriusUser
from rules.tests import RestAPITestBase, RestAPIListTestCase


class RestAPIAccountTestCase(RestAPITestBase, APITestCase):
    def setUp(self):
        RestAPITestBase.setUp(self)

        # Create scirius user is_superuser
        APITestCase.setUp(self)
        self.sciriususer_super = SciriusUser.objects.create(user=self.user, timezone='UTC')

        # Create Scirius User is_staff
        params = {'username': 'sonic_staff', 'timezone': 'UTC', 'password': '69scirius69', 'is_superuser': False, 'is_staff': True, 'is_active': True}
        response = self.http_post(reverse('sciriususer-list'), params, status=status.HTTP_201_CREATED)

        self.sciriususer_staff = SciriusUser.objects.get(pk=response['pk'])
        self.assertEqual(self.sciriususer_staff is not None, True)
        self.assertEqual(self.sciriususer_staff.user.username, 'sonic_staff')

        # Create scirius user is_active
        params = {'username': 'sonic_active', 'timezone': 'UTC', 'password': '69scirius69', 'is_superuser': False, 'is_staff': False, 'is_active': True}
        response = self.http_post(reverse('sciriususer-list'), params, status=status.HTTP_201_CREATED)

        self.sciriususer_active = SciriusUser.objects.get(pk=response['pk'])
        self.assertEqual(self.sciriususer_active.user.username, 'sonic_active')

        # Connect by default with is_staff user
        self.client.force_login(self.sciriususer_staff.user)

    # ################
    # ###### Details
    def test_001_update_user_staff_details_own(self):
        params = {'username': 'sonic_test_done', 'timezone': 'Europe/Paris'}
        self.http_put(reverse('sciriususer-detail', args=(self.sciriususer_staff.pk,)), params)

        # update its own details
        sciriususer_staff = SciriusUser.objects.get(pk=self.sciriususer_staff.pk)
        self.assertEqual(sciriususer_staff is not None, True)
        self.assertEqual(sciriususer_staff.user.username, 'sonic_test_done')
        self.assertEqual(sciriususer_staff.timezone, 'Europe/Paris')

    def test_002_fail_update_user_staff_details_with_user_active(self):
        # Update staff user with active user => forbidden
        self.client.force_login(self.sciriususer_active.user)
        params = {'username': 'sonic_test_forbid', 'timezone': 'UTC'}
        self.http_put(reverse('sciriususer-detail', args=(self.sciriususer_staff.pk,)), params, status=status.HTTP_403_FORBIDDEN)

    def test_003_update_user_staff_details_with_user_super(self):
        # Super user can update another user details
        self.client.force_login(self.user)
        params = {'username': 'sonic_test_allow', 'timezone': 'UTC'}
        response = self.http_put(reverse('sciriususer-detail', args=(self.sciriususer_staff.pk,)), params)

        sciriususer_staff = SciriusUser.objects.get(pk=response['pk'])
        self.assertEqual(sciriususer_staff.user.username, 'sonic_test_allow')
        self.assertEqual(sciriususer_staff.timezone, 'UTC')

    def test_004_fail_update_user_active_details_own(self):
        self.client.force_login(self.sciriususer_active.user)
        params = {'username': 'sonic_test_done', 'timezone': 'Europe/Paris'}
        self.http_put(reverse('sciriususer-detail', args=(self.sciriususer_active.pk,)), params, status=status.HTTP_403_FORBIDDEN)

        # update its own details
        sciriususer_staff = SciriusUser.objects.get(pk=self.sciriususer_active.pk)
        self.assertEqual(sciriususer_staff is not None, True)
        self.assertEqual(sciriususer_staff.user.username, 'sonic_active')
        self.assertEqual(sciriususer_staff.timezone, 'UTC')

    def test_005_fail_update_user_active_details_with_user_staff(self):
        self.client.force_login(self.sciriususer_staff.user)
        params = {'username': 'sonic_test_forbid', 'timezone': 'UTC'}
        self.http_put(reverse('sciriususer-detail', args=(self.sciriususer_active.pk,)), params, status=status.HTTP_403_FORBIDDEN)

    def test_006_update_user_active_details_with_user_super(self):
        # Super user can update another user details
        self.client.force_login(self.user)
        params = {'username': 'sonic_test_allow', 'timezone': 'UTC'}
        response = self.http_put(reverse('sciriususer-detail', args=(self.sciriususer_active.pk,)), params)

        sciriususer_staff = SciriusUser.objects.get(pk=response['pk'])
        self.assertEqual(sciriususer_staff.user.username, 'sonic_test_allow')
        self.assertEqual(sciriususer_staff.timezone, 'UTC')

    def test_007_fail_upgrade_privilege_from_active_to_staff(self):
        self.client.force_login(self.sciriususer_active.user)
        params = {'is_taff': True}
        self.http_put(reverse('sciriususer-detail', args=(self.sciriususer_active.pk,)), params, status=status.HTTP_403_FORBIDDEN)

    def test_008_fail_upgrade_privilege_from_active_to_super(self):
        self.client.force_login(self.sciriususer_active.user)
        params = {'is_superuser': True}
        self.http_put(reverse('sciriususer-detail', args=(self.sciriususer_active.pk,)), params, status=status.HTTP_403_FORBIDDEN)

    def test_009_fail_upgrade_privilege_from_staff_to_super(self):
        self.client.force_login(self.sciriususer_staff.user)
        params = {'is_superuser': True}
        self.http_put(reverse('sciriususer-detail', args=(self.sciriususer_staff.pk,)), params, status=status.HTTP_403_FORBIDDEN)

    def test_010_fail_update_user_active_password_from_details_api_with_user_super(self):
        self.client.force_login(self.user)
        params = {"username": "sonic_active_updated", "password": "51other51"}
        self.http_put(reverse('sciriususer-detail', args=(self.sciriususer_active.pk,)), params, status=status.HTTP_403_FORBIDDEN)

    def test_011_fail_update_user_staff_password_from_details_api_with_user_super(self):
        self.client.force_login(self.user)
        params = {"username": "sonic_staff_updated", "password": "51other51"}
        self.http_put(reverse('sciriususer-detail', args=(self.sciriususer_staff.pk,)), params, status=status.HTTP_403_FORBIDDEN)

    def test_012_fail_update_user_super_password_from_details_api_with_user_super(self):
        self.client.force_login(self.user)
        params = {"username": "sonic_super_updated", "password": "51other51"}
        self.http_put(reverse('sciriususer-detail', args=(self.sciriususer_super.pk,)), params, status=status.HTTP_403_FORBIDDEN)

    # ################
    # ###### Password
    def test_020_fail_update_user_staff_password_own_with_missing_field(self):
        # wrong request
        params = {'new_password': '51scirius51'}
        self.http_post(reverse('sciriususer-password', args=(self.sciriususer_staff.pk,)), params, status=status.HTTP_400_BAD_REQUEST)
        self.assertEqual(self.sciriususer_staff.user.check_password('69scirius69'), True)

    def test_021_update_user_staff_password_own(self):
        # update its own password
        params = {'old_password': '69scirius69', 'new_password': '51scirius51'}
        self.http_post(reverse('sciriususer-password', args=(self.sciriususer_staff.pk,)), params)

        sciriususer = SciriusUser.objects.get(pk=self.sciriususer_staff.pk)
        self.assertEqual(sciriususer.user.check_password('51scirius51'), True)

    def test_022_fail_update_user_active_password_with_user_staff(self):
        # cannot update another user password (is_staff)
        self.client.force_login(self.sciriususer_staff.user)

        params = {'new_password': '51sciriusro51', 'old_password': '69sciriusro69'}
        self.http_post(reverse('sciriususer-password', args=(self.sciriususer_active.pk,)), params, status=status.HTTP_403_FORBIDDEN)

    def test_023_fail_update_user_staff_password_with_user_active(self):
        # cannot update another user password (is_active)
        self.client.force_login(self.sciriususer_active.user)

        params = {'new_password': '51scirius51', 'old_password': '69scirius69'}
        self.http_post(reverse('sciriususer-password', args=(self.sciriususer_staff.pk,)), params, status=status.HTTP_403_FORBIDDEN)

    def test_024_update_user_staff_password_with_user_super(self):
        # can update another user password (superuser)
        self.client.force_login(self.user)

        params = {'new_password': '51scirius51'}
        self.http_post(reverse('sciriususer-password', args=(self.sciriususer_staff.pk,)), params)

    # ################
    # ###### Token
    def test_030_create_user_staff_token_own(self):
        # generate a token
        response = self.http_post(reverse('sciriususer-token', args=(self.sciriususer_staff.pk,)))
        self.assertEqual('token' in response, True)

        # compare with generated token with db token
        token = response['token']
        token_db = Token.objects.filter(user_id=self.sciriususer_staff.user.pk)
        self.assertEqual(token, str(token_db[0]))

    def test_031_get_user_staff_token_own(self):
        # Need to create token before getting it
        self.test_030_create_user_staff_token_own()

        response = self.http_get(reverse('sciriususer-token', args=(self.sciriususer_staff.pk,)))
        self.assertEqual('token' in response, True)

        token = response['token']
        token_db = Token.objects.filter(user_id=self.sciriususer_staff.user.pk)
        self.assertEqual(token, str(token_db[0]))

    def test_032_fail_get_user_staff_token_with_user_active(self):
        self.client.force_login(self.sciriususer_active.user)
        self.http_get(reverse('sciriususer-token', args=(self.sciriususer_staff.pk, )), {}, status=status.HTTP_403_FORBIDDEN)

    def test_033_fail_create_user_staff_token_with_user_active(self):
        self.client.force_login(self.sciriususer_active.user)
        self.http_post(reverse('sciriususer-token', args=(self.sciriususer_staff.pk, )), {}, status=status.HTTP_403_FORBIDDEN)

    def test_034_get_user_active_token_own(self):
        self.client.force_login(self.sciriususer_active.user)
        self.http_get(reverse('sciriususer-token', args=(self.sciriususer_active.pk, )), {}, status=status.HTTP_200_OK)

    def test_035_create_user_active_token_own(self):
        self.client.force_login(self.sciriususer_active.user)
        self.http_post(reverse('sciriususer-token', args=(self.sciriususer_active.pk, )), {}, status=status.HTTP_200_OK)

    # ################
    # ###### List
    def test_040_fail_list_all_users_with_user_active(self):
        self.client.force_login(self.sciriususer_active.user)
        self.http_get(reverse('sciriususer-list'), {}, status=status.HTTP_403_FORBIDDEN)

    def test_041_fail_list_all_users_with_user_staff(self):
        self.client.force_login(self.sciriususer_staff.user)
        self.http_get(reverse('sciriususer-list'), {}, status=status.HTTP_403_FORBIDDEN)

    def test_042_list_all_users_with_user_super(self):
        self.client.force_login(self.user)
        self.http_get(reverse('sciriususer-list'), {}, status=status.HTTP_200_OK)

    def test_043_unique_user(self):
        self.client.force_login(self.user)
        r = self.http_post(reverse('sciriususer-list'), {'username': 'scirius', 'password': 'scirius'}, status=status.HTTP_400_BAD_REQUEST)
        self.assertDictEqual(r, {'username': ['This field must be unique.']})


class RestAPIAccountListTestCase(RestAPIListTestCase):
    def setUp(self):
        super(RestAPIAccountListTestCase, self).setUp()
        self.router = router
