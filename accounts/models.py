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


from django.db import models
from django.contrib.auth.models import User
import pytz

class SciriusUser(models.Model):
    TIMEZONES = ((x, x) for x in pytz.all_timezones)

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    timezone = models.CharField(max_length=40, choices = TIMEZONES)

    def to_dict(self):
        return {
                  "pk": self.pk,
                  "timezone": self.timezone,
                  "username": self.user.username,
                  "first_name": self.user.first_name,
                  "last_name": self.user.last_name,
                  "is_staff": self.user.is_staff,
                  "is_active": self.user.is_active,
                  "is_superuser": self.user.is_superuser,
                  "email": self.user.email,
                  "date_joined": self.user.date_joined
                }
