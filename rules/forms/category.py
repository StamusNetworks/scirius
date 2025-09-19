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
    Category,
    Transformation,
)

from .common import BaseEditForm
from .misc import RulesetPolicyEditPermForm
from .source import RulesetChoiceForm

MIDDLEWARE = __import__(settings.RULESET_MIDDLEWARE)


class CategoryTransformForm(RulesetPolicyEditPermForm, BaseEditForm, RulesetChoiceForm):
    rulesets_label = "Apply transformation(s) to the following ruleset(s)"
    action = forms.ChoiceField()
    lateral = forms.ChoiceField()
    target = forms.ChoiceField()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["action"].choices = Category.get_transformation_choices(key=Transformation.ACTION)
        self.fields["lateral"].choices = Category.get_transformation_choices(key=Transformation.LATERAL)
        self.fields["target"].choices = Category.get_transformation_choices(key=Transformation.TARGET)
