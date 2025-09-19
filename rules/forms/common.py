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
from django.core.exceptions import PermissionDenied
from django.db.models import fields


class CommentForm(forms.Form):
    comment = forms.CharField(widget=forms.Textarea, label="Optional comment", required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Put the comment field at the end of the self.fields ordered dict
        comment = self.fields.pop("comment")
        self.fields["comment"] = comment


class BaseEditForm:
    def __init__(self, *args, **kwargs):
        request = kwargs.pop("request")
        super().__init__(*args, **kwargs)

        self.can_edit = request.user.has_perm(self.WRITE_PERM)
        if not self.can_edit:
            for key in self.fields:
                self.fields[key].disabled = True

        self.fields_changed = []

    def clean(self):
        if not self.can_edit:
            raise PermissionDenied()

        return super().clean()

    def model_has_changed(self):
        if not hasattr(self, "instance"):
            raise Exception("Method allowed only for ModelForm")

        if not hasattr(self, "cleaned_data"):
            raise Exception('"is_valid" must be called before calling this method')

        pk = self.instance.pk
        for field_name, new_value in self.cleaned_data.items():
            if pk:
                instance = self.instance.__class__.objects.filter(pk=pk).first()
                if hasattr(instance, field_name):
                    old_value = getattr(instance, field_name)
                    # set empty string to None to be able to compare
                    old_value = old_value if old_value else None
                    new_value = new_value if new_value else None
                    if old_value != new_value:
                        self.fields_changed.append(field_name)
                # else: form.field_name is different than model.field_name
                # example: form.splunk_key and model.splunk_ssl_key
                # we compare it manually in this case in the view
            else:  # new form/model
                if hasattr(self.instance.__class__, field_name):
                    field = getattr(self.instance.__class__, field_name).field

                    if isinstance(field, fields.CharField) and new_value:
                        self.fields_changed.append(field_name)

        return len(self.fields_changed) > 0

    @property
    def model_changed_data(self):
        return self.fields_changed
