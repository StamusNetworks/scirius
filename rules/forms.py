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
from rules.models import Ruleset, Source, Category, SourceAtVersion, SystemSettings, Threshold

class SystemSettingsForm(forms.ModelForm):
    use_http_proxy = forms.BooleanField(label='Use a proxy', required=False)
    custom_elasticsearch = forms.BooleanField(label='Use a custom Elasticsearch server', required=False)

    class Meta:
        model = SystemSettings
        exclude = []

class KibanaDataForm(forms.Form):
    file = forms.FileField(required = False)

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

    class Meta:
        model = Source
        exclude = ['created_date', 'updated_date']

    def __init__(self, *args, **kwargs):
        super(AddSourceForm, self).__init__(*args, **kwargs)
        ruleset_list =  Ruleset.objects.all()
        if len(ruleset_list):
            self.fields['rulesets'] = forms.ModelMultipleChoiceField(
                        ruleset_list,
                        widget=forms.CheckboxSelectMultiple(),
                        label = "Add source to the following ruleset(s)",
                        required = False)

# Display choices of SourceAtVersion
class RulesetForm(forms.Form):
    name = forms.CharField(max_length=100)
    activate_categories = forms.BooleanField(label = "Activate all categories in sources",
                                             initial = True, required = False)

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

    def __init__(self, *args, **kwargs):
        super(RulesetForm, self).__init__(*args, **kwargs)
        sourceatversion = SourceAtVersion.objects.all()
        self.fields['sources'] = forms.ModelMultipleChoiceField(
                        sourceatversion,
                        widget=forms.CheckboxSelectMultiple())



class RulesetEditForm(forms.ModelForm):
    name = forms.CharField(max_length=100)

    class Meta:
        model = Ruleset
        fields = ('name',)

class RulesetCopyForm(forms.Form):
    name = forms.CharField(max_length=100)

class RulesetSuppressForm(forms.Form):
    def __init__(self, *args, **kwargs):
        super(RulesetSuppressForm, self).__init__(*args, **kwargs)
        rulesets = Ruleset.objects.all().values_list('pk', 'name')
        self.fields['rulesets'] = forms.MultipleChoiceField(rulesets, widget = forms.CheckboxSelectMultiple())

class AddRuleThresholdForm(forms.ModelForm):
    threshold_type = forms.CharField(widget = forms.HiddenInput())
    class Meta:
        model = Threshold
        exclude = ['ruleset', 'rule', 'gid', 'descr', 'net']
    def __init__(self, *args, **kwargs):
        super(AddRuleThresholdForm, self).__init__(*args, **kwargs)
        ruleset_list =  Ruleset.objects.all()
        if len(ruleset_list):
            self.fields['rulesets'] = forms.ModelMultipleChoiceField(
                        ruleset_list,
                        widget=forms.CheckboxSelectMultiple(),
                        label = "Add threshold to the following ruleset(s)",
                        required = True)

class AddRuleSuppressForm(forms.ModelForm):
    threshold_type = forms.CharField(widget = forms.HiddenInput())
    class Meta:
        model = Threshold
        exclude = ['ruleset', 'rule', 'gid', 'descr', 'type', 'count', 'seconds']
    def __init__(self, *args, **kwargs):
        super(AddRuleSuppressForm, self).__init__(*args, **kwargs)
        ruleset_list =  Ruleset.objects.all()
        if len(ruleset_list):
            self.fields['rulesets'] = forms.ModelMultipleChoiceField(
                        ruleset_list,
                        widget=forms.CheckboxSelectMultiple(),
                        label = "Add suppression to the following ruleset(s)",
                        required = True)

class EditThresholdForm(forms.ModelForm):
    class Meta:
        model = Threshold
        exclude = ['pk', 'rule']

class TransformForm(forms.Form):
    type = forms.ChoiceField((('reject', 'Reject'), ('drop', 'Drop'), ('filestore', 'Filestore')))

    def __init__(self, *args, **kwargs):
        super(TransformForm, self).__init__(*args, **kwargs)
        ruleset_list =  Ruleset.objects.all()
        if len(ruleset_list):
            self.fields['rulesets'] = forms.ModelMultipleChoiceField(
                        ruleset_list,
                        widget=forms.CheckboxSelectMultiple(),
                        label = "Apply transformation(s) to the following ruleset(s)",
                        required = False)
