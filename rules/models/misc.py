"""
Copyright(C) 2014-2018 Stamus Networks
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

import re
from copy import deepcopy
from typing import NotRequired, TypedDict

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import validate_ipv4_address
from django.db import models

from scirius.settings import DATA_LIKE


def validate_hostname(val: str):
    try:
        validate_ipv4_address(val)
    except ValidationError:
        # ip may in fact be a hostname
        # http://www.regextester.com/23
        HOSTNAME_RX = r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"
        if not re.match(HOSTNAME_RX, val):
            raise ValidationError("Invalid hostname or IP")


def validate_port(val):
    try:
        val = int(val)
    except ValueError:
        raise ValidationError("Invalid port")


def validate_proxy(val: str):
    if val.startswith(("http://", "https://")):
        val = val.rstrip("/")
        val = val[len("http://"):] if val.startswith("http://") else val[len("https://"):]

        if "@" in val:
            login, val = val.rsplit("@", 1)
            if login.count(":") < 1:
                raise ValidationError("Invalid login, no password found")

    if val.count(":") != 1:
        raise ValidationError("Invalid address")

    host, port = val.split(":")
    validate_hostname(host)
    validate_port(port)


def validate_url(val: str):
    # URL validator that does not require a FQDN
    if not (val.startswith(("http://", "https://"))):
        raise ValidationError("Invalid scheme")

    netloc = val.split("://", 1)[1]
    if "/" in netloc:
        netloc = netloc.split("/", 1)[0]

    if "@" in netloc:
        netloc = netloc.split("@", 1)[1]

    if ":" in netloc:
        netloc, port = netloc.split(":", 1)
        validate_port(port)

    validate_hostname(netloc)


def validate_url_list(value: str):
    for url in value.split(","):
        validate_url(url)


class DeepLink(models.Model):
    name = models.CharField(max_length=128, null=False, blank=False)
    template = models.CharField(max_length=2048, validators=[validate_url], null=False, blank=False)
    all = models.BooleanField(default=False)

    class Meta:
        unique_together = ("name", "template")


class DeepLinkEntity(models.Model):
    deeplink = models.ManyToManyField(DeepLink, related_name="entities", blank=True)
    name = models.CharField(max_length=128, null=False, blank=False)


class FakePermissionModel(models.Model):
    """
    This fake model with no database table will generate a contenttype id
    that will be used with all permissions.
    This way, permissions are not linked with models.
    Ref: https://stackoverflow.com/questions/13932774/how-can-i-use-django-permissions-without-defining-a-content-type-or-model
    """

    class Meta:
        managed = False
        default_permissions = ()


class SystemSettings(models.Model):
    use_http_proxy = models.BooleanField(default=False)
    http_proxy = models.CharField(
        max_length=200,
        validators=[validate_proxy],
        default="",
        blank=True,
        help_text='Proxy address of the form "host:port".',
    )
    https_proxy = models.CharField(max_length=200, validators=[validate_proxy], default="", blank=True)
    custom_elasticsearch = models.BooleanField(default=False)
    elasticsearch_url = models.CharField(
        max_length=4096,
        validators=[validate_url_list],
        blank=False,
        null=False,
        default="http://elasticsearch:9200/",
        help_text="Comma separated list of elasticsearch url",
    )
    use_proxy_for_es = models.BooleanField(default=False)
    custom_cookie_age = models.FloatField("Age of session cookies", default=360)
    elasticsearch_user = models.CharField("Elasticsearch username", max_length=4096, blank=True, default="")
    elasticsearch_pass = models.CharField("Elasticsearch password", max_length=4096, blank=True, default="")
    custom_login_banner = models.TextField("Add your own banner on login page", blank=True, default="")
    session_cookie_age = models.IntegerField(default=0)

    @property
    def use_arkime(self):
        return settings.USE_MOLOCH

    @staticmethod
    def has_es7_behavior():
        ES_7 = DATA_LIKE.ES_7
        OS_1 = DATA_LIKE.OS_1
        return settings.USE_DATA_LIKE in (ES_7, OS_1)

    @staticmethod
    def use_opensearch_2():
        return settings.USE_DATA_LIKE == DATA_LIKE.OS_2

    @staticmethod
    def use_elasticsearch_6():
        return settings.USE_DATA_LIKE == DATA_LIKE.ES_6

    @staticmethod
    def use_elasticsearch_8():
        return settings.USE_DATA_LIKE == DATA_LIKE.ES_8

    @staticmethod
    def use_elasticsearch():
        return settings.USE_DATA_LIKE in (DATA_LIKE.ES_6, DATA_LIKE.ES_7, DATA_LIKE.ES_8)

    @staticmethod
    def use_opensearch():
        return settings.USE_DATA_LIKE in (DATA_LIKE.OS_1, DATA_LIKE.OS_2)

    @property
    def arkime_url(self):
        return "/arkime"

    def get_proxy_params(self):
        if self.use_http_proxy:
            return {"http": self.http_proxy, "https": self.https_proxy}
        return None

    def save(self, *args, **kwargs) -> None:
        from rules.es_query import build_es_url
        from scirius.utils import get_middleware_module

        if self.custom_elasticsearch:
            es_url = build_es_url(self.elasticsearch_url, self.elasticsearch_user, self.elasticsearch_pass)
            get_middleware_module("common").check_es_template_needed(es_url)

        super().save(*args, **kwargs)


def get_system_settings(static=False):
    if static:
        return SystemSettings

    gsettings = SystemSettings.objects.first()
    if gsettings is None:
        gsettings = SystemSettings.objects.create()
        if settings.USE_PROXY:
            gsettings.use_http_proxy = True
            gsettings.http_proxy = settings.PROXY_PARAMS["http"]
            gsettings.https_proxy = settings.PROXY_PARAMS["https"]
        else:
            gsettings.use_http_proxy = False
        gsettings.save()
    return gsettings


def get_es_address():
    from rules.es_query import ESQuery

    return ESQuery.get_es_address()


class FilterValueItem(TypedDict):
    id: str
    title: str
    placeholder: NotRequired[str]


class FilterCategoryItem(TypedDict):
    id: str
    title: str
    placeholder: NotRequired[str]
    filterValues: list[FilterValueItem]


class HuntFilterItem(TypedDict):
    id: str
    title: str
    placeholder: str
    filterType: str
    valueType: str
    queryType: str
    filterCategories: NotRequired[list[FilterCategoryItem]]


_HUNT_FILTERS: list[HuntFilterItem] = [
    {
        "id": "hits_min",
        "title": "Alerts min",
        "placeholder": "Minimum Hits Count",
        "filterType": "number",
        "valueType": "positiveint",
        "queryType": "rest",
    },
    {
        "id": "hits_max",
        "title": "Alerts max",
        "placeholder": "Maximum Hits Count",
        "filterType": "number",
        "valueType": "positiveint",
        "queryType": "rest",
    },
    {
        "id": "ip",
        "title": "IP",
        "placeholder": "Filter by IP",
        "filterType": "text",
        "valueType": "ip",
        "queryType": "filter",
    },
    {
        "id": "host",
        "title": "Probe",
        "placeholder": "Filter by Probes",
        "filterType": "text",
        "valueType": "text",
        "queryType": "filter",
    },
    {
        "id": "msg",
        "title": "Message",
        "placeholder": "Filter by Message",
        "filterType": "text",
        "valueType": "text",
        "queryType": "filter",
    },
    {
        "id": "not_in_msg",
        "title": "Not in Message",
        "placeholder": "Filter by not in Message",
        "filterType": "text",
        "valueType": "text",
        "queryType": "filter",
    },
    {
        "id": "content",
        "title": "Content",
        "placeholder": "Filter by Content",
        "filterType": "text",
        "valueType": "text",
        "queryType": "rest",
    },
    {
        "id": "not_in_content",
        "title": "Not in Content",
        "placeholder": "Filter by not in Content",
        "filterType": "text",
        "valueType": "text",
        "queryType": "rest",
    },
    {
        "id": "port",
        "title": "Port",
        "placeholder": "Filter by Port (src/dest)",
        "filterType": "number",
        "valueType": "positiveint",
        "queryType": "filter",
    },
    {
        "id": "alert.signature_id",
        "title": "Signature ID",
        "placeholder": "Filter by Signature ID",
        "filterType": "number",
        "valueType": "positiveint",
        "queryType": "filter",
    },
    {
        "id": "es_filter",
        "title": "ES Filter",
        "placeholder": "Free ES Filter",
        "filterType": "text",
        "valueType": "text",
        "queryType": "filter",
    },
    {
        "id": "protocol",
        "title": "Protocol",
        "placeholder": "Filter by Protocol",
        "filterType": "complex-select-text",
        "filterCategoriesPlaceholder": "Filter by type",
        "queryType": "filter",
        "filterCategories": [
            {
                "id": "dns",
                "title": "DNS",
                "filterValues": [
                    {"id": "query.rrname", "title": "Query Name"},
                    {"id": "query.rrtype", "title": "Query Type"},
                ],
            },
            {
                "id": "http",
                "title": "HTTP",
                "filterValues": [
                    {"id": "http_user_agent", "title": "User-Agent", "placeholder": "Filter by User Agent"},
                    {"id": "hostname", "title": "Host", "placeholder": "Filter by Host"},
                    {"id": "url", "title": "URL", "placeholder": "Filter by URL"},
                    {"id": "status", "title": "Status", "placeholder": "Filter by Status"},
                    {"id": "http_method", "title": "Method", "placeholder": "Filter by Method"},
                    {"id": "http_content_type", "title": "Content Type", "placeholder": "Filter by Content Type"},
                    {"id": "length", "title": "Length", "placeholder": "Filter by Content Length"},
                ],
            },
            {
                "id": "smtp",
                "title": "SMTP",
                "filterValues": [
                    {"id": "mail_from", "title": "From", "placeholder": "Filter by From"},
                    {"id": "rcpt_to", "title": "To", "placeholder": "Filter by To"},
                    {"id": "helo", "title": "Helo", "placeholder": "Filter by Helo"},
                ],
            },
            {
                "id": "smb",
                "title": "SMB",
                "filterValues": [
                    {"id": "command", "title": "Command", "placeholder": "Filter by Command"},
                    {"id": "status", "title": "Status", "placeholder": "Filter by Status"},
                    {"id": "filename", "title": "Filename", "placeholder": "Filter by Filename"},
                    {"id": "share", "title": "Share", "placeholder": "Filter by Share"},
                ],
            },
            {
                "id": "ssh",
                "title": "SSH",
                "filterValues": [
                    {
                        "id": "client.software_version",
                        "title": "Client Software",
                        "placeholder": "Filter by Client Software",
                    },
                    {
                        "id": "client.proto_version",
                        "title": "Client Version",
                        "placeholder": "Filter by Client Version",
                    },
                    {
                        "id": "server.software_version",
                        "title": "Server Software",
                        "placeholder": "Filter by Server Software",
                    },
                    {
                        "id": "server.proto_version",
                        "title": "Server Version",
                        "placeholder": "Filter by Server Version",
                    },
                ],
            },
            {
                "id": "tls",
                "title": "TLS",
                "filterValues": [
                    {"id": "subject", "title": "Subject DN", "placeholder": "Filter by Subject DN"},
                    {"id": "issuerdn", "title": "Issuer DN", "placeholder": "Filter by Issuer DN"},
                    {"id": "sni", "title": "Server Name Indication", "placeholder": "Filter by Server Name Indication"},
                    {"id": "version", "title": "Version", "placeholder": "Filter by Version"},
                    {"id": "fingerprint", "title": "Fingerprint", "placeholder": "Filter by Fingerprint"},
                    {"id": "serial", "title": "Serial", "placeholder": "Filter by Serial"},
                    {"id": "ja3.hash", "title": "JA3 Hash", "placeholder": "Filter by JA3 Hash"},
                    {"id": "ja3s.hash", "title": "JA3S Hash", "placeholder": "Filter by JA3S Hash"},
                ],
            },
        ],
    },
]


def get_hunt_filters() -> list[HuntFilterItem]:
    return deepcopy(_HUNT_FILTERS)


# probably unused
def build_iprep_name(msg: str) -> str:
    return re.sub("[^0-9a-zA-Z]+", "_", msg.replace(" ", ""))
