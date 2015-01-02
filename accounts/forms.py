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

from django import forms
from django.contrib.auth.models import User
import pytz

class LoginForm(forms.Form):
    username = forms.CharField(max_length=20)
    password = forms.CharField(widget=forms.PasswordInput)

TIMEZONES = ((x, x) for x in pytz.all_timezones)

class UserSettingsForm(forms.ModelForm):
    timezone = forms.ChoiceField(choices = TIMEZONES)
    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'email', 'timezone', 'is_active', 'is_superuser', 'is_staff']

class NormalUserSettingsForm(forms.ModelForm):
    timezone = forms.ChoiceField(choices = TIMEZONES)
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'is_active']
