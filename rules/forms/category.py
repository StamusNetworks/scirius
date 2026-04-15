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

from rules.models.model import Transformation

from .common import BaseEditForm
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
        A_RULESET_DEFAULT = Transformation.A_RULESET_DEFAULT
        A_NONE = Transformation.A_NONE

        # TODO: move me in settings.RULESET_TRANSFORMATIONS
        allowed_choices.append((A_BYPASS.value, A_BYPASS.name.title()))
        allowed_choices.append((A_RULESET_DEFAULT.value, A_RULESET_DEFAULT.name.replace("_", " ").title()))
        allowed_choices.append((A_NONE.value, A_NONE.name.title()))

    if key == TARGET:
        CAT_DEFAULT = Transformation.T_CAT_DEFAULT
        allowed_choices = list(Transformation.TargetTransfoType.get_choices())
        allowed_choices.remove((CAT_DEFAULT.value, CAT_DEFAULT.name.replace("_", " ").title()))

    if key == LATERAL:
        CAT_DEFAULT = Transformation.L_CAT_DEFAULT
        allowed_choices = list(Transformation.LateralTransfoType.get_choices())
        allowed_choices.remove((CAT_DEFAULT.value, CAT_DEFAULT.name.replace("_", " ").title()))

    return tuple(sorted(allowed_choices))


class CategoryTransformForm(RulesetPolicyEditPermForm, BaseEditForm, RulesetChoiceForm):
    rulesets_label = "Apply transformation(s) to the following ruleset(s)"
    action = forms.ChoiceField()
    lateral = forms.ChoiceField()
    target = forms.ChoiceField()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["action"].choices = get_transformation_choices(key=Transformation.ACTION)
        self.fields["lateral"].choices = get_transformation_choices(key=Transformation.LATERAL)
        self.fields["target"].choices = get_transformation_choices(key=Transformation.TARGET)
