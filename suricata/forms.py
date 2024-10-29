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
from django.conf import settings
from scirius.utils import convert_to_utc
from suricata.models import CeleryTask, Suricata, RecurrentTask
from rules.forms import CommentForm, ConfigurationEditPermForm, BaseEditForm


class SuricataForm(forms.ModelForm, CommentForm):
    class Meta:
        model = Suricata
        exclude = ('created_date', 'updated_date')
        if settings.SURICATA_NAME_IS_HOSTNAME:
            exclude = exclude + ('name', )


class SuricataUpdateForm(CommentForm):
    reload = forms.BooleanField(required=False)
    push = forms.BooleanField(required=False)
    schedule = forms.BooleanField(required=False)
    schedule_param = forms.DateTimeField(required=False, input_formats=['%Y/%m/%d %H:%M'])
    recurrence = forms.BooleanField(required=False)
    recurrence_param = forms.CharField(max_length=40, required=False)

    def clean(self):
        cleaned_data = super().clean()
        if not cleaned_data.get('reload', False) and not cleaned_data.get('push', False):
            self.add_error(field=None, error='You must select an action.')
        return cleaned_data

    def spawn(self, user, ruleset_pk):
        schedule = None
        if self.cleaned_data['schedule'] and self.cleaned_data['schedule_param']:
            schedule = convert_to_utc(self.cleaned_data['schedule_param'], user)

        recurrence = None
        if self.cleaned_data['recurrence'] and self.cleaned_data['recurrence_param']:
            recurrence = self.cleaned_data['recurrence_param']

        task = CeleryTask.spawn(
            'UpdateGenerateRuleset',
            user=user,
            schedule=schedule,
            recurrence=recurrence,
            update=self.cleaned_data.get('reload', False),
            generate=self.cleaned_data.get('push', False),
            ruleset_pk=ruleset_pk
        )
        return task


class EditRecurrentTaskForm(ConfigurationEditPermForm, BaseEditForm, forms.ModelForm, CommentForm):
    schedule_param = forms.DateTimeField(required=False, input_formats=['%Y/%m/%d %H:%M'])
    recurrence_param = forms.CharField(max_length=40, required=False)

    class Meta:
        model = RecurrentTask
        fields = ('schedule_param', 'recurrence_param')

    def __init__(self, *args, **kwargs):
        self.request = kwargs.get('request')
        super().__init__(*args, **kwargs)

    def save(self, _=False):
        schedule = convert_to_utc(self.cleaned_data['schedule_param'], self.request.user)
        recurrence = self.cleaned_data['recurrence_param']

        self.instance.scheduled = schedule
        self.instance.recurrence = recurrence
        self.instance.save()
