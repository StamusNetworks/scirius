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

from __future__ import unicode_literals
from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import PasswordChangeForm as DjangoPasswordChangeForm
from django.contrib.auth.forms import UserCreationForm as DjangoUserCreationForm
import pytz

from rules.forms import CommentForm


class PasswordChangeForm(DjangoPasswordChangeForm):
    comment = forms.CharField(widget=forms.Textarea,
                              label="Optional comment",
                              required=False)

    def __init__(self, *args, **kwargs):
        super(PasswordChangeForm, self).__init__(*args, **kwargs)

        # Put the comment field at the end of the self.fields ordered dict
        comment = self.fields.pop('comment')
        self.fields['comment'] = comment


class UserCreationForm(DjangoUserCreationForm):
    comment = forms.CharField(widget=forms.Textarea,
                              label="Optional comment",
                              required=False)

    def __init__(self, *args, **kwargs):
        super(UserCreationForm, self).__init__(*args, **kwargs)

        # Put the comment field at the end of the self.fields ordered dict
        comment = self.fields.pop('comment')
        self.fields['comment'] = comment


class LoginForm(forms.Form):
    username = forms.CharField(max_length=150)
    password = forms.CharField(widget=forms.PasswordInput)
    persistent = forms.BooleanField(label="Remember this browser.", required = False)

TIMEZONES = ((x, x) for x in pytz.all_timezones)

class UserSettingsForm(forms.ModelForm, CommentForm):
    TIMEZONES = ((x, x) for x in pytz.all_timezones)
    timezone = forms.ChoiceField(choices = TIMEZONES)
    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'email', 'timezone', 'is_active', 'is_superuser', 'is_staff']

class NormalUserSettingsForm(forms.ModelForm, CommentForm):
    TIMEZONES = ((x, x) for x in pytz.all_timezones)
    timezone = forms.ChoiceField(choices = TIMEZONES)
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'timezone']

class PasswordForm(CommentForm):
    password = forms.CharField(label="New user password", widget=forms.PasswordInput)

class DeleteForm(CommentForm):
    confirm = forms.IntegerField()

    def __init__(self, *args, **kwargs):
        super(DeleteForm, self).__init__(*args, **kwargs)
        self.fields['confirm'].widget = forms.HiddenInput()

class TokenForm(CommentForm):
    token = forms.CharField(label="Token", required=False)

    def __init__(self, *args, **kwargs):
        super(TokenForm, self).__init__(*args, **kwargs)
        self.fields['token'].widget.attrs['readonly'] = True
