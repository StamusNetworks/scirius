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

import tarfile
import json
from io import BytesIO
from django import forms
from django.core.exceptions import NON_FIELD_ERRORS, PermissionDenied, ValidationError
from django.core.serializers.json import DjangoJSONEncoder
from django.db.models import F, fields
from django.db import transaction
from django.conf import settings
from rules.models import (
    Ruleset, Source, Category, SystemSettings, Threshold, Transformation,
    RuleProcessingFilter, RuleProcessingFilterDef, FilterSet, validate_source_datatype
)


class RulesetPolicyEditPermForm:
    WRITE_PERM = 'rules.ruleset_policy_edit'


class ConfigurationEditPermForm:
    WRITE_PERM = 'rules.configuration_edit'


class CommentForm(forms.Form):
    comment = forms.CharField(widget=forms.Textarea, label="Optional comment", required=False)

    def __init__(self, *args, **kwargs):
        super(CommentForm, self).__init__(*args, **kwargs)

        # Put the comment field at the end of the self.fields ordered dict
        comment = self.fields.pop('comment')
        self.fields['comment'] = comment


class RulesetChoiceForm(CommentForm):
    rulesets = forms.ModelMultipleChoiceField(None, widget=forms.CheckboxSelectMultiple(), required=True)

    def __init__(self, *args, **kwargs):
        super(RulesetChoiceForm, self).__init__(*args, **kwargs)
        ruleset_list = Ruleset.objects.all()
        self.fields['rulesets'].queryset = ruleset_list

        if hasattr(self, 'rulesets_label'):
            self.fields['rulesets'].label = self.rulesets_label

        if not len(ruleset_list):
            if not (isinstance(self, AddSourceForm) or isinstance(self, AddPublicSourceForm)):
                self.errors[NON_FIELD_ERRORS] = ['Please create a ruleset first']
            self.fields.pop('rulesets')


class BaseEditForm:
    def __init__(self, *args, **kwargs):
        request = kwargs.pop('request')
        super().__init__(*args, **kwargs)

        self.can_edit = request.user.has_perm(self.WRITE_PERM)
        if not self.can_edit:
            for key in self.fields.keys():
                self.fields[key].disabled = True

        self.fields_changed = []

    def clean(self):
        if not self.can_edit:
            raise PermissionDenied()

        return super().clean()

    def model_has_changed(self):
        if not hasattr(self, 'instance'):
            raise Exception('Method allowed only for ModelForm')

        if not hasattr(self, 'cleaned_data'):
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


class SystemSettingsForm(ConfigurationEditPermForm, BaseEditForm, forms.ModelForm, CommentForm):
    use_http_proxy = forms.BooleanField(label='Use a proxy', required=False)
    custom_elasticsearch = forms.BooleanField(label='Use an external Elasticsearch server', required=False)
    http_proxy = forms.CharField(max_length=200, required=False, help_text='Proxy address of the form "http://username:password@hostname:port/"')
    elasticsearch_url = forms.CharField(max_length=200, empty_value='http://elasticsearch:9200/', required=False)
    use_proxy_for_es = forms.BooleanField(label='Use elasticsearch with system proxy', required=False)
    custom_cookie_age = forms.FloatField(
        label='Automatic logout after inactivity timeout (in hours)',
        required=True,
        min_value=0.5,
    )
    elasticsearch_user = forms.CharField(required=False, help_text='Elasticsearch username for %s' % settings.APP_SHORT_NAME)
    elasticsearch_pass = forms.CharField(required=False,
                                         label='Elasticsearch password',
                                         help_text='Elasticsearch password for %s' % settings.APP_SHORT_NAME,
                                         widget=forms.PasswordInput(render_value=True))
    custom_login_banner = forms.CharField(
        required=False,
        label='Custom login page banner text',
        widget=forms.Textarea(
            attrs={
                'rows': 3,
                'style': 'resize: none;',
                'placeholder': 'Enter the plain text that will be displayed on login page'
            }
        )
    )

    class Meta:
        model = SystemSettings
        exclude = []

    def clean_elasticsearch_url(self):
        if self.cleaned_data['custom_elasticsearch'] and '@' in self.cleaned_data['elasticsearch_url']:
            raise forms.ValidationError('Credentials must be set in the dedicated fields')
        return self.cleaned_data['elasticsearch_url']


class KibanaDataForm(forms.Form):
    file = forms.FileField(required=False)


class PoliciesForm(RulesetPolicyEditPermForm, BaseEditForm, forms.Form):
    file = forms.FileField(required=True)

    @staticmethod
    def _import(file_, delete):
        from scirius.utils import get_middleware_module

        with tarfile.open(fileobj=file_, mode='r:gz') as tar:
            policy = tar.getmember('policies.json')
            content = json.loads(tar.extractfile(policy).read().decode())

            with transaction.atomic():
                if delete:
                    removed_indexes = list(RuleProcessingFilter.objects.filter(imported=True).order_by('-index').values_list('index', flat=True))
                    RuleProcessingFilter.objects.filter(imported=True).delete()

                    for index in removed_indexes:
                        RuleProcessingFilter.objects.filter(index__gt=index).update(index=F('index') - 1)

                    FilterSet.objects.filter(user_id=None, imported=True).delete()
                    get_middleware_module('common').delete_policies()

                if len(content) > 0:
                    RuleProcessingFilter.objects.update(index=F('index') + len(content))

                for item in content:
                    extra_policies = get_middleware_module('common').extract_policies(item)

                    filter_defs_list = item.pop('filter_defs')
                    rulesets = item.pop('rulesets')

                    item['imported'] = True
                    filter_ = RuleProcessingFilter.objects.create(**item)
                    filter_.rulesets.set(Ruleset.objects.filter(name__in=rulesets))

                    for filter_defs in filter_defs_list:
                        filter_defs['proc_filter'] = filter_
                        filter_defs = RuleProcessingFilterDef.objects.create(**filter_defs)

                    if extra_policies:
                        extra_policies.update({'filter_': filter_})
                        get_middleware_module('common').import_policies(**extra_policies)

                filterset = tar.getmember('filtersets.json')
                content = json.loads(tar.extractfile(filterset).read().decode())

                for item in content:
                    item['imported'] = True
                    FilterSet.objects.get_or_create(**item)

    @staticmethod
    def _export():
        from scirius.utils import get_middleware_module

        filter_fields = [f.name for f in RuleProcessingFilter._meta.get_fields() if f.name not in ('id', 'ruleset')]
        filterdef_fields = [f.name for f in RuleProcessingFilterDef._meta.get_fields() if f.name not in ('id', 'proc_filter')]
        filterset_fields = [f.name for f in FilterSet._meta.get_fields() if f.name not in ('id', 'user')]

        res = []
        for proc_filter in RuleProcessingFilter.objects.values(*filter_fields):
            proc_filter['filter_defs'] = list(RuleProcessingFilterDef.objects.filter(pk=proc_filter['filter_defs']).values(*filterdef_fields))
            proc_filter['rulesets'] = list(Ruleset.objects.filter(pk=proc_filter['rulesets']).values_list('name', flat=True))

            get_middleware_module('common').update_policies(proc_filter)

            res.append(proc_filter)

        # Get only shared filtersets
        json_filtersets = json.dumps(list(FilterSet.objects.filter(user_id=None).values(*filterset_fields)))
        json_content = json.dumps(res, cls=DjangoJSONEncoder)

        tar_path_io = BytesIO()
        with tarfile.open(fileobj=tar_path_io, mode="w:gz") as tar:
            policy_info = tarfile.TarInfo('policies.json')
            policy_info.size = len(json_content)
            tar.addfile(policy_info, BytesIO(bytes(json_content, 'utf-8')))

            filtersets_info = tarfile.TarInfo('filtersets.json')
            filtersets_info.size = len(json_filtersets)
            tar.addfile(filtersets_info, BytesIO(bytes(json_filtersets, 'utf-8')))

        return tar_path_io


class SourceForm(forms.ModelForm, CommentForm):
    file = forms.FileField(required=False)
    authkey = forms.CharField(max_length=100,
                              label="Optional authorization key",
                              required=False,
                              widget=forms.PasswordInput(render_value=True))
    untrusted = forms.BooleanField(label='Source sanitization', required=False, help_text='If you uncheck the box then signatures can potentially modify the probe or run arbitrary code.', initial=True)

    class Meta:
        model = Source
        exclude = ['created_date', 'updated_date', 'cats_count', 'rules_count', 'public_source', 'version']

    def __init__(self, *args, **kwargs):
        source = kwargs.get('instance', None)
        super(SourceForm, self).__init__(*args, **kwargs)

        from scirius.utils import get_middleware_module
        extra_choices = get_middleware_module('common').update_source_content_type(source)
        self.fields['datatype'] = forms.ChoiceField(choices=Source.CONTENT_TYPE + extra_choices)


class AddSourceForm(forms.ModelForm, RulesetChoiceForm):
    file = forms.FileField(required=False)
    authkey = forms.CharField(max_length=100, label="Optional authorization key", required=False)
    rulesets_label = "Add source to the following ruleset(s)"
    untrusted = forms.BooleanField(label='Source sanitization', required=False, help_text='If you uncheck the box then signatures can potentially modify the probe or run arbitrary code.', initial=True)

    class Meta:
        model = Source
        exclude = ['created_date', 'updated_date', 'cats_count', 'rules_count', 'public_source', 'version']

    def __init__(self, *args, **kwargs):
        super(AddSourceForm, self).__init__(*args, **kwargs)
        if 'rulesets' in self.fields:
            self.fields['rulesets'].required = False

        from scirius.utils import get_middleware_module
        extra_choices = get_middleware_module('common').update_source_content_type()
        self.fields['datatype'] = forms.ChoiceField(choices=Source.CONTENT_TYPE + extra_choices)

    def clean(self):
        cleaned_data = super().clean()
        datatype = cleaned_data['datatype']

        try:
            validate_source_datatype(datatype)
        except ValidationError as e:
            self.add_error('datatype', e.message)

        return cleaned_data


class AddPublicSourceForm(forms.ModelForm, RulesetChoiceForm):
    source_id = forms.CharField(max_length=100)
    secret_code = forms.CharField(max_length=100, required=False)
    use_iprep = forms.BooleanField(required=False)
    untrusted = forms.BooleanField(label='Source sanitization', required=False, help_text='If you uncheck the box then signatures can potentially modify the probe or run arbitrary code.', initial=True)

    class Meta:
        model = Source
        exclude = ['created_date', 'updated_date', 'cats_count', 'rules_count', 'method', 'datatype', 'version']

    def __init__(self, *args, **kwargs):
        super(AddPublicSourceForm, self).__init__(*args, **kwargs)
        if 'rulesets' in self.fields:
            self.fields['rulesets'].required = False


# Display choices of Source
class RulesetForm(CommentForm):
    name = forms.CharField(max_length=100)
    sources = forms.ModelMultipleChoiceField(None, widget=forms.CheckboxSelectMultiple())
    activate_categories = forms.BooleanField(label="Activate all categories in selected sources", initial=True, required=False)

    rulesets_label = "Apply transformation(s) to the following ruleset(s)"
    action = forms.ChoiceField()
    lateral = forms.ChoiceField()
    target = forms.ChoiceField()

    def __init__(self, *args, **kwargs):
        super(RulesetForm, self).__init__(*args, **kwargs)

        self.fields['sources'].queryset = Source.objects.all()
        self.fields['action'].choices = Ruleset.get_transformation_choices(key=Transformation.ACTION)
        self.fields['lateral'].choices = Ruleset.get_transformation_choices(key=Transformation.LATERAL)
        self.fields['target'].choices = Ruleset.get_transformation_choices(key=Transformation.TARGET)


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
        widget=forms.Textarea
    )

    class Meta:
        model = Ruleset
        fields = ('name', 'action', 'lateral', 'target', 'suppressed_sids')

    def __init__(self, *args, **kwargs):
        super(RulesetEditForm, self).__init__(*args, **kwargs)
        self.fields['action'].choices = Ruleset.get_transformation_choices(key=Transformation.ACTION)
        self.fields['lateral'].choices = Ruleset.get_transformation_choices(key=Transformation.LATERAL)
        self.fields['target'].choices = Ruleset.get_transformation_choices(key=Transformation.TARGET)

    def clean_suppressed_sids(self):
        suppressed_sids = self.cleaned_data['suppressed_sids']
        suppressed_sids = suppressed_sids.replace('\r', '')
        return suppressed_sids


class RulesetCopyForm(CommentForm):
    name = forms.CharField(max_length=100)


class RulesetSuppressForm(RulesetChoiceForm):
    rulesets_label = "Modify object in the following ruleset(s)"


class AddRuleThresholdForm(forms.ModelForm, RulesetChoiceForm):
    rulesets_label = "Add threshold to the following ruleset(s)"
    threshold_type = forms.CharField(widget=forms.HiddenInput())

    class Meta:
        model = Threshold
        exclude = ['ruleset', 'rule', 'gid', 'descr', 'net']


class AddRuleSuppressForm(forms.ModelForm, RulesetChoiceForm):
    rulesets_label = "Add suppression to the following ruleset(s)"
    threshold_type = forms.CharField(widget=forms.HiddenInput())
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


class CategoryTransformForm(RulesetPolicyEditPermForm, BaseEditForm, RulesetChoiceForm):
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
    comment = forms.CharField(widget=forms.Textarea)
