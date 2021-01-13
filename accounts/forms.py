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
from django.contrib.auth.models import User, Group as DjangoGroup
from django.contrib.auth.forms import PasswordChangeForm as DjangoPasswordChangeForm, UserCreationForm
from django.db.models import Max, F
import pytz

from .models import Group, SciriusUser

from scirius.utils import get_middleware_module
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


class GroupEditForm(forms.ModelForm, CommentForm):
    DEFAULT_GROUPS = ('Superuser', 'Staff', 'User')

    name = forms.CharField(required=True)
    permissions = forms.ModelMultipleChoiceField(None, widget=forms.CheckboxSelectMultiple(), label='', required=False)
    ldap_group = forms.CharField(required=False)
    priority = forms.IntegerField(help_text='Smallest value has highest priority in Group/Role assignment', required=True)
    comment = forms.CharField(
        widget=forms.Textarea,
        label="Optional comment",
        required=False
    )

    class Meta:
        model = DjangoGroup
        fields = ('name', 'permissions', 'ldap_group', 'priority', 'comment')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['permissions'].queryset = DjangoGroup.objects.filter(name='Superuser').first().permissions
        self.fields['permissions'].choices = DjangoGroup.objects.filter(name='Superuser').first().permissions.order_by('pk').values_list('pk', 'name')
        self.mapping = dict(DjangoGroup.objects.filter(name='Superuser').first().permissions.values_list('pk', 'codename'))

        if not get_middleware_module('common').has_extra_auth():
            self.fields.pop('ldap_group')
            self.fields.pop('priority')

        instance = kwargs.get('instance', None)
        if instance:
            self.initial['permissions'] = instance.permissions.values_list('pk', flat=True)
            self.initial['name'] = instance.name
            self.initial['ldap_group'] = instance.group.ldap_group

        if get_middleware_module('common').has_extra_auth():
            priority = Group.objects.aggregate(Max('priority'))['priority__max']
            if not instance:
                priority += 1
            self.fields['priority'].widget = forms.NumberInput(attrs={'max': priority, 'min': len(self.DEFAULT_GROUPS)})
            self.fields['priority'].initial = instance.group.priority if instance else priority

        # Put the comment field at the end of the self.fields ordered dict
        comment = self.fields.pop('comment')
        self.fields['comment'] = comment

        if instance:
            if instance.name in self.DEFAULT_GROUPS:
                for key in self.fields.keys():
                    if key not in ('ldap_group', 'comment'):
                        self.fields[key].disabled = True

    def save(self, commit=True):
        instance = super().save(commit=commit)

        created = False
        instance.permissions.add(*self.cleaned_data['permissions'])
        try:
            group = instance.group
            instance.name = self.cleaned_data['name']
            instance.group.ldap_group = self.cleaned_data.get('ldap_group', '')
        except AttributeError:
            group = Group.objects.create(
                group=instance,
                ldap_group=self.cleaned_data.get('ldap_group', '')
            )
            created = True

        if 'priority' in self.cleaned_data:
            new_priority = self.cleaned_data['priority']
            old_priority = self.instance.group.priority if not created else Group.objects.count() - 1
            max_priority = Group.objects.aggregate(Max('priority'))['priority__max']

            if new_priority <= max_priority:
                if old_priority > new_priority:
                    Group.objects.filter(
                        priority__gte=new_priority,
                        priority__lt=old_priority
                    ).update(priority=F('priority') + 1)
                elif old_priority < new_priority:
                    Group.objects.filter(
                        priority__lte=new_priority,
                        priority__gt=old_priority
                    ).update(priority=F('priority') - 1)

            group.priority = new_priority
            group.save()
        return instance


class LoginForm(forms.Form):
    username = forms.CharField(max_length=150)
    password = forms.CharField(widget=forms.PasswordInput)
    persistent = forms.BooleanField(label="Remember this browser.", required=False)


TIMEZONES = ((x, x) for x in pytz.all_timezones)


class PasswordCreationForm(UserCreationForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields.pop('username')


class UserSettingsForm(forms.ModelForm, CommentForm):
    TIMEZONES = ((x, x) for x in pytz.all_timezones)

    timezone = forms.ChoiceField(choices=TIMEZONES)
    groups = forms.ModelChoiceField(None, label='Role')
    tenants = forms.ModelMultipleChoiceField(None, widget=forms.CheckboxSelectMultiple(), label='', required=False)
    all_tenants = forms.BooleanField(required=False)
    no_tenant = forms.BooleanField(required=False)

    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'email', 'timezone', 'groups', 'is_active', 'no_tenant', 'all_tenants', 'tenants']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        instance = kwargs.get('instance', None)
        if not get_middleware_module('common').has_multitenant():
            self.fields.pop('tenants')
            self.fields.pop('no_tenant')
            self.fields.pop('all_tenants')
        else:
            self.fields['tenants'].queryset = get_middleware_module('common').get_tenants()

            if instance:
                self.fields['tenants'].initial = instance.sciriususer.get_tenants()
                self.fields['all_tenants'].initial = instance.sciriususer.has_all_tenants()
                self.fields['no_tenant'].initial = instance.sciriususer.has_no_tenant()

        self.fields['groups'].queryset = DjangoGroup.objects.order_by('name')
        if instance:
            # self.fields['groups'].initial does not work
            self.initial['groups'] = instance.groups.first().pk if instance.groups.count() > 0 else ''
            self.fields['timezone'].initial = instance.sciriususer.timezone
        else:
            self.fields['timezone'].initial = 'UTC'
            self.initial['groups'] = Group.objects.order_by('-priority').first()

    def clean(self):
        cleaned_data = super().clean()
        if 'groups' in cleaned_data:
            cleaned_data['groups'] = [cleaned_data['groups']]
        return cleaned_data

    def save(self, commit=True):
        '''
        Do not support commit==False
        '''
        if not commit:
            raise NotImplementedError('This method does not support "commit=True"')

        instance = super().save()
        try:
            sciriususer = instance.sciriususer
            sciriususer.timezone = self.cleaned_data['timezone']
        except AttributeError:
            sciriususer = SciriusUser.objects.create(
                user=instance,
                timezone=self.cleaned_data['timezone'],
            )

        instance.save()
        get_middleware_module('common').update_scirius_user_class(instance, self.cleaned_data)
        return instance


class NormalUserSettingsForm(forms.ModelForm, CommentForm):
    TIMEZONES = ((x, x) for x in pytz.all_timezones)
    timezone = forms.ChoiceField(choices=TIMEZONES)

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'timezone']


class PasswordForm(CommentForm):
    password = forms.CharField(label="New user password", widget=forms.PasswordInput)


class TokenForm(CommentForm):
    token = forms.CharField(label="Token", required=False)

    def __init__(self, *args, **kwargs):
        super(TokenForm, self).__init__(*args, **kwargs)
        self.fields['token'].widget.attrs['readonly'] = True
