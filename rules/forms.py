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
from django.core.exceptions import NON_FIELD_ERRORS
from rules.models import Ruleset, Rule, Source, Category, SourceAtVersion, SystemSettings, Threshold, UserAction, Transformation


class CommentForm(forms.Form):
    comment = forms.CharField(widget=forms.Textarea,
                              label = "Optional comment",
                              required = False)

    def __init__(self, *args, **kwargs):
        super(CommentForm, self).__init__(*args, **kwargs)

        # Put the comment field at the end of the self.fields ordered dict
        comment = self.fields.pop('comment')
        self.fields['comment'] = comment

class RulesetChoiceForm(CommentForm):
    rulesets = forms.ModelMultipleChoiceField(None,
                        widget=forms.CheckboxSelectMultiple(),
                        required=True)

    def __init__(self, *args, **kwargs):
        super(RulesetChoiceForm, self).__init__(*args, **kwargs)
        ruleset_list =  Ruleset.objects.all()
        self.fields['rulesets'].queryset = ruleset_list

        if hasattr(self, 'rulesets_label'):
            self.fields['rulesets'].label = self.rulesets_label

        if not len(ruleset_list):
            if not (isinstance(self, AddSourceForm) or isinstance(self, AddPublicSourceForm)):
                self.errors[NON_FIELD_ERRORS] = ['Please create a ruleset first']
            self.fields.pop('rulesets')

class SystemSettingsForm(forms.ModelForm, CommentForm):
    use_http_proxy = forms.BooleanField(label='Use a proxy', required=False)
    custom_elasticsearch = forms.BooleanField(label='Use a custom Elasticsearch server', required=False)
    http_proxy = forms.CharField(max_length=200, required=False, help_text='Proxy address of the form "http://username:password@hostname:port/"')
    elasticsearch_url = forms.CharField(max_length=200, empty_value='http://elasticsearch:9200/', required=False)

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
        exclude = ['created_date', 'updated_date', 'cats_count', 'rules_count', 'public_source', 'version']

    def __init__(self, *args, **kwargs):
        source = kwargs.get('instance', None)
        super(SourceForm, self).__init__(*args, **kwargs)

        from scirius.utils import get_middleware_module
        choices = get_middleware_module('common').update_source_content_type(Source.CONTENT_TYPE, source)
        self.fields['datatype'] = forms.ChoiceField(choices=choices)


class AddSourceForm(forms.ModelForm, RulesetChoiceForm):
    file  = forms.FileField(required = False)
    authkey = forms.CharField(max_length=100,
                              label = "Optional authorization key",
                              required = False)
    rulesets_label = "Add source to the following ruleset(s)"

    class Meta:
        model = Source
        exclude = ['created_date', 'updated_date', 'cats_count', 'rules_count', 'public_source', 'version']

    def __init__(self, *args, **kwargs):
        super(AddSourceForm, self).__init__(*args, **kwargs)
        if 'rulesets' in self.fields:
            self.fields['rulesets'].required =  False

        from scirius.utils import get_middleware_module
        choices = get_middleware_module('common').update_source_content_type(Source.CONTENT_TYPE)
        self.fields['datatype'] = forms.ChoiceField(choices=choices)


class AddPublicSourceForm(forms.ModelForm, RulesetChoiceForm):
    source_id = forms.CharField(max_length=100)
    secret_code = forms.CharField(max_length=100, required = False)
    use_iprep = forms.BooleanField(required=False)

    class Meta:
        model = Source
        exclude = ['created_date', 'updated_date', 'cats_count', 'rules_count', 'method', 'datatype', 'version']

    def __init__(self, *args, **kwargs):
        super(AddPublicSourceForm, self).__init__(*args, **kwargs)
        if 'rulesets' in self.fields:
            self.fields['rulesets'].required =  False

# Display choices of SourceAtVersion
class RulesetForm(CommentForm):
    name = forms.CharField(max_length=100)
    sources = forms.ModelMultipleChoiceField(None, widget=forms.CheckboxSelectMultiple())
    activate_categories = forms.BooleanField(label = "Activate all categories in selected sources",
                                             initial = True, required = False)

    rulesets_label = "Apply transformation(s) to the following ruleset(s)"
    action = forms.ChoiceField()
    lateral = forms.ChoiceField()
    target = forms.ChoiceField()


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

        from scirius.utils import get_middleware_module
        sourceatversion = SourceAtVersion.objects.exclude(source__datatype__in=get_middleware_module('common').custom_source_datatype(True))
        self.fields['sources'].queryset = sourceatversion
        self.fields['action'].choices = Ruleset.get_transformation_choices(key=Transformation.ACTION)
        self.fields['lateral'].choices = Ruleset.get_transformation_choices(key=Transformation.LATERAL)
        self.fields['target'].choices = Ruleset.get_transformation_choices(key=Transformation.TARGET)


class RulesetEditForm(forms.ModelForm, CommentForm):
    name = forms.CharField(max_length=100)

    rulesets_label = "Apply transformation(s) to the following ruleset(s)"
    action = forms.ChoiceField()
    lateral = forms.ChoiceField()
    target = forms.ChoiceField()

    class Meta:
        model = Ruleset
        fields = ('name', 'action', 'lateral', 'target')

    def __init__(self, *args, **kwargs):
        super(RulesetEditForm, self).__init__(*args, **kwargs)
        self.fields['action'].choices = Ruleset.get_transformation_choices(key=Transformation.ACTION)
        self.fields['lateral'].choices = Ruleset.get_transformation_choices(key=Transformation.LATERAL)
        self.fields['target'].choices = Ruleset.get_transformation_choices(key=Transformation.TARGET)


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
    net = forms.CharField(required=True)

    class Meta:
        model = Threshold
        exclude = ['ruleset', 'rule', 'gid', 'descr', 'type', 'count', 'seconds']

    def clean(self):
        cleaned_data = super(AddRuleSuppressForm, self).clean()
        if 'net' in cleaned_data and ',' in cleaned_data['net']:
            cleaned_data['net'] = ','.join([item.strip() for item in cleaned_data['net'].split(',')])


class EditThresholdForm(forms.ModelForm, CommentForm):
    class Meta:
        model = Threshold
        exclude = ['pk', 'rule']

class RuleTransformForm(RulesetChoiceForm):
    rulesets_label = "Apply transformation(s) to the following ruleset(s)"
    action = forms.ChoiceField()
    lateral = forms.ChoiceField()
    target = forms.ChoiceField()

    def __init__(self, *args, **kwargs):
        rule = kwargs.pop('instance')

        super(RuleTransformForm, self).__init__(*args, **kwargs)
        choices = rule.get_transformation_choices(key=Transformation.ACTION)
        self.fields['action'].choices = choices
        self.fields['lateral'].choices = rule.get_transformation_choices(key=Transformation.LATERAL)
        self.fields['target'].choices = rule.get_transformation_choices(key=Transformation.TARGET)


class CategoryTransformForm(RulesetChoiceForm):
    rulesets_label = "Apply transformation(s) to the following ruleset(s)"
    action = forms.ChoiceField()
    lateral = forms.ChoiceField()
    target = forms.ChoiceField()

    def __init__(self, *args, **kwargs):
        super(CategoryTransformForm, self).__init__(*args, **kwargs)
        self.fields['action'].choices = Category.get_transformation_choices(key=Transformation.ACTION)
        self.fields['lateral'].choices = Category.get_transformation_choices(key=Transformation.LATERAL)
        self.fields['target'].choices = Category.get_transformation_choices(key=Transformation.TARGET)


class RuleCommentForm(forms.Form):
    comment = forms.CharField(widget = forms.Textarea)
