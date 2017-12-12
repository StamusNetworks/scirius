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
from django.conf import settings
from rules.models import Ruleset, Rule, Source, Category, SourceAtVersion, SystemSettings, Threshold, UserAction


class CommentForm(forms.Form):
    comment = forms.CharField(widget=forms.Textarea,
                              label = "Optional comment",
                              required = False)

class RulesetChoiceForm(CommentForm):
    rulesets_label = "Add object to the following ruleset(s)"

    def __init__(self, *args, **kwargs):
        super(RulesetChoiceForm, self).__init__(*args, **kwargs)
        ruleset_list =  Ruleset.objects.all()
        if len(ruleset_list):
            self.fields['rulesets'] = forms.ModelMultipleChoiceField(
                        ruleset_list,
                        widget=forms.CheckboxSelectMultiple(),
                        label = self.rulesets_label,
                        required=True)
        comment = self.fields.pop('comment')
        self.fields['comment'] = comment

class SystemSettingsForm(forms.ModelForm):
    use_http_proxy = forms.BooleanField(label='Use a proxy', required=False)
    custom_elasticsearch = forms.BooleanField(label='Use a custom Elasticsearch server', required=False)

    class Meta:
        model = SystemSettings
        exclude = []

class KibanaDataForm(forms.Form):
    file = forms.FileField(required = False)

class SourceForm(forms.ModelForm, CommentForm):
    file = forms.FileField(required = False)
    authkey = forms.CharField(max_length=100,
                              label = "Optional authorization key",
                              required = False,
                              widget = forms.PasswordInput(render_value = True))
    class Meta:
        model = Source
        exclude = ['created_date', 'updated_date']

class AddSourceForm(forms.ModelForm, RulesetChoiceForm):
    file  = forms.FileField(required = False)
    authkey = forms.CharField(max_length=100,
                              label = "Optional authorization key",
                              required = False)
    rulesets_label = "Add source to the following ruleset(s)"

    class Meta:
        model = Source
        exclude = ['created_date', 'updated_date']

    def __init__(self, *args, **kwargs):
        super(AddSourceForm, self).__init__(*args, **kwargs)
        if 'rulesets' in self.fields:
            self.fields['rulesets'].required =  False

# Display choices of SourceAtVersion
class RulesetForm(CommentForm):
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
        comment = self.fields.pop('comment')
        self.fields['comment'] = comment

class RulesetEditForm(forms.ModelForm, CommentForm):
    name = forms.CharField(max_length=100)

    class Meta:
        model = Ruleset
        fields = ('name',)

class RulesetCopyForm(CommentForm):
    name = forms.CharField(max_length=100)

class RulesetSuppressForm(RulesetChoiceForm):
    rulesets_label = "Modify object in the following ruleset(s)"

class AddRuleThresholdForm(forms.ModelForm, RulesetChoiceForm):
    rulesets_label = "Add threshold to the following ruleset(s)"
    threshold_type = forms.CharField(widget = forms.HiddenInput())
    class Meta:
        model = Threshold
        exclude = ['ruleset', 'rule', 'gid', 'descr', 'net']

class AddRuleSuppressForm(forms.ModelForm, RulesetChoiceForm):
    rulesets_label = "Add suppression to the following ruleset(s)"
    threshold_type = forms.CharField(widget = forms.HiddenInput())
    class Meta:
        model = Threshold
        exclude = ['ruleset', 'rule', 'gid', 'descr', 'type', 'count', 'seconds']

class EditThresholdForm(forms.ModelForm, CommentForm):
    class Meta:
        model = Threshold
        exclude = ['pk', 'rule']

class RuleTransformForm(forms.ModelForm, RulesetChoiceForm):
    rulesets_label = "Apply transformation(s) to the following ruleset(s)"

    class Meta:
        model = Rule
        fields = []

    def __init__(self, *args, **kwargs):
        super(RuleTransformForm, self).__init__(*args, **kwargs)
        trans = self.instance.get_transform()
        trans += (('none', 'None'), ('category', 'Category default'))
        self.fields['type'] = forms.ChoiceField(trans)
        comment = self.fields.pop('comment')
        self.fields['comment'] = comment

class CategoryTransformForm(RulesetChoiceForm):
    rulesets_label = "Apply transformation(s) to the following ruleset(s)"

    def __init__(self, *args, **kwargs):
        super(CategoryTransformForm, self).__init__(*args, **kwargs)
        trans = settings.RULESET_TRANSFORMATIONS + (('none', 'None'),)
        self.fields['type'] = forms.ChoiceField(trans)
        comment = self.fields.pop('comment')
        self.fields['comment'] = comment

class RuleCommentForm(forms.Form):
    comment = forms.CharField(widget = forms.Textarea)

class OptionalCommentForm(forms.Form):
    comment = forms.CharField(label = "Optional comment", widget = forms.Textarea, required = False)
