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

from rules.models import (
    Ruleset,
    Source,
    Transformation,
)

from .common import BaseEditForm, CommentForm
from .misc import RulesetPolicyEditPermForm
from .source import RulesetChoiceForm


MIDDLEWARE = __import__(settings.RULESET_MIDDLEWARE)


# Display choices of Source
class RulesetForm(CommentForm):
    name = forms.CharField(max_length=100)
    sources = forms.ModelMultipleChoiceField(None, widget=forms.CheckboxSelectMultiple())
    activate_categories = forms.BooleanField(
        label="Activate all categories in selected sources", initial=True, required=False
    )

    rulesets_label = "Apply transformation(s) to the following ruleset(s)"
    action = forms.ChoiceField()
    lateral = forms.ChoiceField()
    target = forms.ChoiceField()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields["sources"].queryset = Source.objects.all()
        self.fields["action"].choices = Ruleset.get_transformation_choices(key=Transformation.ACTION)
        self.fields["lateral"].choices = Ruleset.get_transformation_choices(key=Transformation.LATERAL)
        self.fields["target"].choices = Ruleset.get_transformation_choices(key=Transformation.TARGET)


class RulesetEditForm(RulesetPolicyEditPermForm, BaseEditForm, forms.ModelForm, CommentForm):
    name = forms.CharField(max_length=100)
    rulesets_label = "Apply transformation(s) to the following ruleset(s)"
    action = forms.ChoiceField()
    lateral = forms.ChoiceField()
    target = forms.ChoiceField()
    suppressed_sids = forms.CharField(
        label="Suppress events",
        help_text="Ex: suppress gen_id 1, sig_id 2003614, track by_src, ip 217.110.97.128/25",
        required=False,
        widget=forms.Textarea,
    )

    class Meta:
        model = Ruleset
        fields = ("name", "action", "lateral", "target", "suppressed_sids")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["action"].choices = Ruleset.get_transformation_choices(key=Transformation.ACTION)
        self.fields["lateral"].choices = Ruleset.get_transformation_choices(key=Transformation.LATERAL)
        self.fields["target"].choices = Ruleset.get_transformation_choices(key=Transformation.TARGET)

    def clean_suppressed_sids(self):
        suppressed_sids = self.cleaned_data["suppressed_sids"]
        return suppressed_sids.replace("\r", "")


class RulesetCopyForm(CommentForm):
    name = forms.CharField(max_length=100)


class RulesetSuppressForm(RulesetChoiceForm):
    rulesets_label = "Modify object in the following ruleset(s)"
