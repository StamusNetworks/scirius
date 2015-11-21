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
from django.utils import timezone
from rules.models import Ruleset, Source, Category, SourceAtVersion, SystemSettings
from datetime import datetime

class SystemSettingsForm(forms.ModelForm):
    class Meta:
        model = SystemSettings
        exclude = []

class SourceForm(forms.ModelForm):
    file = forms.FileField(required = False)
    authkey = forms.CharField(max_length=100,
                              label = "Optional authorization key",
                              required = False)
    class Meta:
        model = Source
        exclude = ['created_date', 'updated_date']

class AddSourceForm(forms.ModelForm):
    file  = forms.FileField(required = False)
    authkey = forms.CharField(max_length=100,
                              label = "Optional authorization key",
                              required = False)
    ruleset_list =  Ruleset.objects.all()
    if len(ruleset_list):
        rulesets = forms.ModelMultipleChoiceField(
                    ruleset_list,
                    widget=forms.CheckboxSelectMultiple(),
                    label = "Add source to the following ruleset(s)",
                    required = False)
    class Meta:
        model = Source
        exclude = ['created_date', 'updated_date']

# Display choices of SourceAtVersion
class RulesetForm(forms.Form):
    name = forms.CharField(max_length=100)
    activate_categories = forms.BooleanField(label = "Activate all categories in sources",
                                             initial = True, required = False)
    sourceatversion = SourceAtVersion.objects.all()
    sources = forms.ModelMultipleChoiceField(
                    sourceatversion,
                    widget=forms.CheckboxSelectMultiple())

    def create_ruleset(self):
        ruleset = Ruleset.objects.create(name = self.cleaned_data['name'],
                    created_date = timezone.now(),
                    updated_date = timezone.now(),
                    )
        for src in self.cleaned_data['sources']:
            ruleset.sources.add(src)
            if self.cleaned_data['activate_categories']:
                for cat in Category.objects.filter(source = src.source):
                    ruleset.categories.add(cat)
        return ruleset

class RulesetEditForm(forms.Form):
    name = forms.CharField(max_length=100)
    categories = forms.MultipleChoiceField(Category.objects.all())

class RulesetCopyForm(forms.Form):
    name = forms.CharField(max_length=100)

class RulesetSuppressForm(forms.Form):
    rulesets = Ruleset.objects.all()
    ruleset = forms.ModelChoiceField(rulesets, empty_label=None)
