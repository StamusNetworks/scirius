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

from urllib.parse import urlparse
from typing import ClassVar, Iterable

from django import forms
from django.conf import settings

from rules.models.misc import SystemSettings

from .common import BaseEditForm, CommentForm

MIDDLEWARE = __import__(settings.RULESET_MIDDLEWARE)


class RulesetPolicyEditPermForm:
    WRITE_PERM = "rules.ruleset_policy_edit"


class ConfigurationEditPermForm:
    WRITE_PERM = "rules.configuration_edit"


class SystemSettingsForm(ConfigurationEditPermForm, BaseEditForm, forms.ModelForm, CommentForm):
    use_http_proxy = forms.BooleanField(label="Use a proxy", required=False)
    custom_elasticsearch = forms.BooleanField(label="Use an external Elasticsearch server", required=False)
    http_proxy = forms.CharField(
        max_length=200, required=False, help_text='Proxy address of the form "http://username:password@hostname:port/"'
    )
    ssl_proxy = forms.BooleanField(
        label="Verify HTTP proxy certificate.",
        help_text="For self signed certificates it must be disabled and the full TLS chain is not verified.",
        required=False,
    )
    elasticsearch_url = forms.CharField(
        max_length=200,
        empty_value="http://elasticsearch:9200/",
        required=False,
        help_text='"http(s)://ip:port" or "http(s)://domain:port"',
    )
    use_proxy_for_es = forms.BooleanField(label="Use elasticsearch with system proxy", required=False)
    custom_cookie_age = forms.FloatField(
        label="Automatic logout after inactivity timeout (in hours)",
        required=True,
        min_value=0.25,
    )
    session_cookie_age = forms.IntegerField(
        label="Automatic logout after timeout (in hours)",
        required=True,
        min_value=0,
    )
    elasticsearch_user = forms.CharField(
        required=False, help_text=f"Elasticsearch username for {settings.APP_SHORT_NAME}"
    )
    elasticsearch_pass = forms.CharField(
        required=False,
        label="Elasticsearch password",
        help_text=f"Elasticsearch password for {settings.APP_SHORT_NAME}",
        widget=forms.PasswordInput(render_value=True),
    )
    custom_login_banner = forms.CharField(
        required=False,
        label="Custom login page banner text",
        widget=forms.Textarea(
            attrs={
                "rows": 3,
                "style": "resize: none;",
                "placeholder": "Enter the plain text that will be displayed on login page",
            }
        ),
    )

    class Meta:
        model = SystemSettings
        exclude: ClassVar[Iterable[str]] = []

    def clean_elasticsearch_url(self):
        if self.cleaned_data["custom_elasticsearch"]:
            if "@" in self.cleaned_data["elasticsearch_url"]:
                raise forms.ValidationError("Credentials must be set in the dedicated fields")
            if self.cleaned_data["elasticsearch_url"]:
                for url in self.cleaned_data["elasticsearch_url"].split(","):
                    parser = urlparse(url)
                    if parser.port is None:
                        raise forms.ValidationError("Invalid syntax: port is missing")
        return self.cleaned_data["elasticsearch_url"]


class KibanaDataForm(forms.Form):
    file = forms.FileField(required=False)
