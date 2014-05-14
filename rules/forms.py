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
from rules.models import Ruleset, Source, Category, SourceAtVersion
from datetime import datetime

class SourceForm(forms.ModelForm):
    class Meta:
        model = Source
        exclude = ['created_date', 'updated_date']

# Display choices of SourceAtVersion
class RulesetForm(forms.Form):
    name = forms.CharField(max_length=100)
    sourceatversion = SourceAtVersion.objects.all()
    sources = forms.ModelMultipleChoiceField(
                    sourceatversion,
                    widget=forms.CheckboxSelectMultiple())

    def create_ruleset(self):
        ruleset = Ruleset.objects.create(name = self.cleaned_data['name'],
                    created_date = datetime.now(),
                    updated_date = datetime.now(),
                    )
        for source in self.cleaned_data['sources']:
            ruleset.sources.add(source)
        return ruleset

class RulesetEditForm(forms.Form):
    name = forms.CharField(max_length=100)
    categories = forms.MultipleChoiceField(Category.objects.all())

class RulesetCopyForm(forms.Form):
    name = forms.CharField(max_length=100)

class RuleSuppressForm(forms.Form):
    rulesets = Ruleset.objects.all()
    ruleset = forms.ModelChoiceField(rulesets, empty_label=None)
