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
from django.conf import settings
from suricata.models import Suricata
from rules.models import Ruleset
from rules.forms import CommentForm

class SuricataForm(forms.ModelForm, CommentForm):
    class Meta:
        model = Suricata
        exclude = ('created_date', 'updated_date')
        if settings.SURICATA_NAME_IS_HOSTNAME:
            exclude = exclude + ('name', )

class SuricataUpdateForm(CommentForm):
    reload = forms.BooleanField(required=False)
    build = forms.BooleanField(required=False)
    push = forms.BooleanField(required=False)
