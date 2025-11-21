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

import tempfile
from typing import ClassVar, Iterable

from django import forms
from django.conf import settings
from django.core.exceptions import ValidationError, NON_FIELD_ERRORS

from rules.models.model import Category, IoCMeta, Source, Ruleset, validate_source_datatype, RuleAtVersion
from rules.validators import no_space_validator

from .common import CommentForm


MIDDLEWARE = __import__(settings.RULESET_MIDDLEWARE)


class RulesetChoiceForm(CommentForm):
    rulesets = forms.ModelMultipleChoiceField(None, widget=forms.CheckboxSelectMultiple(), required=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        ruleset_list = Ruleset.objects.all()
        self.fields["rulesets"].queryset = ruleset_list

        if hasattr(self, "rulesets_label"):
            self.fields["rulesets"].label = self.rulesets_label

        if not ruleset_list.count():
            if not (isinstance(self, (AddSourceForm, AddPublicSourceForm))):
                self.errors[NON_FIELD_ERRORS] = ["Please create a ruleset first"]
            self.fields.pop("rulesets")


class SourceForm(forms.ModelForm, CommentForm):
    file = forms.FileField(required=False)
    authkey = forms.CharField(
        max_length=100,
        label="Optional authorization key",
        required=False,
        widget=forms.PasswordInput(render_value=True),
    )
    untrusted = forms.BooleanField(
        label="Source sanitization",
        required=False,
        help_text="If you uncheck the box then signatures can potentially modify the probe or run arbitrary code.",
        initial=True,
    )

    class Meta:
        model = Source
        exclude: ClassVar[Iterable[str]] = [
            "created_date",
            "updated_date",
            "cats_count",
            "rules_count",
            "public_source",
            "version",
            "is_stamus",
        ]

    def __init__(self, *args, **kwargs):
        source = kwargs.get("instance")
        super().__init__(*args, **kwargs)

        from scirius.utils import get_middleware_module

        extra_choices = get_middleware_module("common").update_source_content_type(source)
        self.fields["datatype"] = forms.ChoiceField(choices=Source.CONTENT_TYPE + extra_choices)
        self.fields["datatype"].disabled = True

        if source.datatype in dict(Source.CONTENT_TYPE):
            self.fields.pop("remove_original_sids")
            if source.datatype == "ioc":
                self.fields["name"].disabled = True
                self.fields["ioc_type"].disabled = True

    def clean(self):
        cleaned_data = super().clean()
        # validate file content
        # validation is done in the task if method is http
        if cleaned_data["method"] == "local" and cleaned_data.get("file") and self.instance.datatype == "ioc":
            validator = Source.IOC_MAPPING[self.instance.ioc_type]["validator"]
            file = cleaned_data["file"]

            for line in file:
                try:
                    validator(line.decode().strip())
                except ValidationError as e:
                    self.add_error("file", e.message)
                    # if we have set a wrong file with 1000 items
                    # we avoid to show all errors on the page
                    break
            file.seek(0)
        return cleaned_data

    def update(self, request, prev_uri, prev_method):
        need_update = False

        # task is run only if a new dataset is uploaded
        kwargs = {}
        if self.instance.method == "local":
            if "file" in request.FILES:
                file_ = request.FILES["file"]
                with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
                    kwargs = {"path": tmpfile.name}
                    for chunk in file_.chunks():
                        tmpfile.write(chunk)

                need_update = True
            else:
                # we don t run a task because we don t have uploaded file
                # we just update the rules
                self.instance._update_ioc_rules()

        # do a soft reset of rules in the source if URL changes
        elif (self.instance.method == "http" and self.instance.uri != prev_uri) or self.instance.method != prev_method:
            RuleAtVersion.objects.filter(rule__category__source=self.instance).update(rev=0)
            self.instance.version = 1
            self.instance.save()

        if self.instance.datatype == "sig":
            # first import if category is None
            category = Category.objects.filter(source=self.instance).first()

            if "name" in self.changed_data and category:
                category.name = "{} Sigs".format(self.cleaned_data["name"])
                category.save()

        if need_update:
            MIDDLEWARE.models.CeleryTask.spawn(
                "SourceUpdateParentTask", source_pk=self.instance.pk, user=request.user, **kwargs
            )

        return need_update


class IoCMetaForm(forms.ModelForm):
    key = forms.CharField(
        max_length=100,
        widget=forms.TextInput(attrs={"class": "form-control"}),
        required=True,
        validators=[no_space_validator],
    )
    value = forms.CharField(
        max_length=100,
        widget=forms.TextInput(attrs={"class": "form-control"}),
        required=True,
        validators=[no_space_validator],
    )

    class Meta:
        model = IoCMeta
        fields = ("key", "value")


class IoCMetaFormset(forms.BaseModelFormSet):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for form in self.forms:
            form.empty_permitted = False

    # https://docs.djangoproject.com/en/2.2/topics/forms/formsets/#adding-additional-fields-to-a-formset
    def add_fields(self, form, index):
        super().add_fields(form, index)
        form.fields["DELETE"].widget = forms.HiddenInput()

    def clean(self):
        if any(self.errors):
            return None

        for form in self.forms:
            if self.can_delete and self._should_delete_form(form):
                continue

        return super().clean()


def get_ioc_meta_formset():
    return forms.modelformset_factory(IoCMeta, can_delete=True, form=IoCMetaForm, formset=IoCMetaFormset, extra=0)


class AddSourceForm(forms.ModelForm, RulesetChoiceForm):
    file = forms.FileField(required=False)
    authkey = forms.CharField(max_length=100, label="Optional authorization key", required=False)
    rulesets_label = "Add source to the following ruleset(s)"
    untrusted = forms.BooleanField(
        label="Source sanitization",
        required=False,
        help_text="If you uncheck the box then signatures can potentially modify the probe or run arbitrary code.",
        initial=True,
    )
    ioc_type = forms.ChoiceField(choices=Source.IOC_TYPE, required=False, label="IoC datatype")

    class Meta:
        model = Source
        exclude: ClassVar[Iterable[str]] = [
            "created_date",
            "updated_date",
            "cats_count",
            "rules_count",
            "public_source",
            "version",
            "is_stamus",
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if "rulesets" in self.fields:
            self.fields["rulesets"].required = False

        from scirius.utils import get_middleware_module

        extra_choices = get_middleware_module("common").update_source_content_type()
        self.fields["datatype"] = forms.ChoiceField(choices=Source.CONTENT_TYPE + extra_choices)

    def clean(self):
        cleaned_data = super().clean()
        datatype = cleaned_data["datatype"]

        try:
            validate_source_datatype(datatype)
        except ValidationError as e:
            self.add_error("datatype", e.message)

        if cleaned_data.get("method") == "local":
            if cleaned_data.get("file") is None:
                self.add_error("file", "This field is required.")
            else:
                if cleaned_data["datatype"] == "ioc":
                    validator = Source.IOC_MAPPING[cleaned_data["ioc_type"]]["validator"]
                    file = cleaned_data["file"]
                    file.seek(0)

                    if validator:
                        for line in file:
                            try:
                                validator(line.decode().strip())
                            except ValidationError as e:
                                self.add_error("file", e.message)
                                # if we have set a wrong file with 1000 items
                                # we avoid to show all errors on the page
                                break

        return cleaned_data

    def update(self, request):
        path = None
        if self.instance.method == "local":
            file_ = request.FILES["file"]
            with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
                for chunk in file_.chunks():
                    tmpfile.write(chunk)
                path = tmpfile.name

        MIDDLEWARE.models.CeleryTask.spawn(
            "SourceUpdateParentTask", source_pk=self.instance.pk, user=request.user, path=path, add=True
        )


class AddPublicSourceForm(forms.ModelForm, RulesetChoiceForm):
    source_id = forms.CharField(max_length=100)
    secret_code = forms.CharField(max_length=100, required=False)
    use_iprep = forms.BooleanField(required=False)
    untrusted = forms.BooleanField(
        label="Source sanitization",
        required=False,
        help_text="If you uncheck the box then signatures can potentially modify the probe or run arbitrary code.",
        initial=True,
    )

    class Meta:
        model = Source
        exclude: ClassVar[Iterable[str]] = [
            "created_date",
            "updated_date",
            "cats_count",
            "rules_count",
            "method",
            "datatype",
            "version",
        ]

    def __init__(self, *args, **kwargs):
        self.public_sources = kwargs.pop("public_sources", None)
        super().__init__(*args, **kwargs)
        if "rulesets" in self.fields:
            self.fields["rulesets"].required = False

    def update(self, request):
        MIDDLEWARE.models.CeleryTask.spawn(
            "SourceUpdateParentTask", source_pk=self.instance.pk, user=request.user, path=None, add=True
        )

    def save(self, commit=False):
        source_id = self.cleaned_data["source_id"]
        source = self.public_sources["sources"][source_id]
        source_uri = source["url"]
        params = {"__version__": "7.0.3"}
        if "secret_code" in self.cleaned_data:
            params.update({"secret-code": self.cleaned_data["secret_code"]})
        source_uri = source_uri % params

        instance = super().save(commit)
        instance.method = "http"
        instance.untrusted = self.cleaned_data.get("untrusted", False)
        instance.cert_verif = True
        instance.uri = source_uri
        instance.public_source = source_id
        instance.datatype = source["datatype"]
        instance.save()
        return instance
