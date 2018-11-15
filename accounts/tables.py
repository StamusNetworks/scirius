"""
Copyright(C) 2014, Stamus Networks
Written by Eric Leblond <eleblond@stamus-networks.com>

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

from django.contrib.auth.models import User
from scirius.utils import SciriusTable
import django_tables2 as tables

class DefaultMeta:
    attrs = {"class": "paleblue"}

class UserTable(SciriusTable):
    username = tables.LinkColumn('user', args=[tables.A('pk')])

    class Meta(DefaultMeta):
        model = User
        fields = ("username", "first_name", "last_name", "email", "is_staff", "is_superuser", "is_active")
