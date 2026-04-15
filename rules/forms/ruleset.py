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

from rules.models.model import Ruleset, Source, Transformation

from .common import BaseEditForm, CommentForm
from .misc import RulesetPolicyEditPermForm
from .source import RulesetChoiceForm


MIDDLEWARE = __import__(settings.RULESET_MIDDLEWARE)


def get_transformation_choices(key=Transformation.ACTION):
    # Keys
    ACTION = Transformation.ACTION
    LATERAL = Transformation.LATERAL
    TARGET = Transformation.TARGET

    allowed_choices = []

    if key == ACTION:
        all_choices_set = set(Transformation.ActionTransfoType.get_choices())
        allowed_choices = list(all_choices_set.intersection(set(settings.RULESET_TRANSFORMATIONS)))

        A_BYPASS = Transformation.A_BYPASS
        A_NONE = Transformation.A_NONE

        # TODO: move me in settings.RULESET_TRANSFORMATIONS
        allowed_choices.append((A_BYPASS.value, A_BYPASS.name.title()))
        allowed_choices.append((A_NONE.value, A_NONE.name.title()))

    if key == TARGET:
        CAT_DEFAULT = Transformation.T_CAT_DEFAULT
        RULESET_DEFAULT = Transformation.T_RULESET_DEFAULT

        allowed_choices = list(Transformation.TargetTransfoType.get_choices())
        allowed_choices.remove((CAT_DEFAULT.value, CAT_DEFAULT.name.replace("_", " ").title()))
        allowed_choices.remove((RULESET_DEFAULT.value, RULESET_DEFAULT.name.replace("_", " ").title()))

    if key == LATERAL:
        CAT_DEFAULT = Transformation.L_CAT_DEFAULT
        RULESET_DEFAULT = Transformation.L_RULESET_DEFAULT

        allowed_choices = list(Transformation.LateralTransfoType.get_choices())
        allowed_choices.remove((CAT_DEFAULT.value, CAT_DEFAULT.name.replace("_", " ").title()))
        allowed_choices.remove((RULESET_DEFAULT.value, RULESET_DEFAULT.name.replace("_", " ").title()))

    return tuple(allowed_choices)


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
        self.fields["action"].choices = get_transformation_choices(key=Transformation.ACTION)
        self.fields["lateral"].choices = get_transformation_choices(key=Transformation.LATERAL)
        self.fields["target"].choices = get_transformation_choices(key=Transformation.TARGET)


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
        self.fields["action"].choices = get_transformation_choices(key=Transformation.ACTION)
        self.fields["lateral"].choices = get_transformation_choices(key=Transformation.LATERAL)
        self.fields["target"].choices = get_transformation_choices(key=Transformation.TARGET)

    def clean_suppressed_sids(self):
        suppressed_sids = self.cleaned_data["suppressed_sids"]
        return suppressed_sids.replace("\r", "")


class RulesetCopyForm(CommentForm):
    name = forms.CharField(max_length=100)


class RulesetSuppressForm(RulesetChoiceForm):
    rulesets_label = "Modify object in the following ruleset(s)"
