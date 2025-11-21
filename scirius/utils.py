"""
Copyright(C) 2014,2015,  Stamus Networks
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


from typing import Any
import datetime
import pytz
from importlib import import_module
from pathlib import Path
from time import time
import httpx
import json
import os
import ssl

from django.shortcuts import render
from django.conf import settings
from django.core.signing import JSONSerializer as DjangoJSONSerializer
from django.utils import timezone
from django.contrib import messages
from django.db.models.query import QuerySet
from django.utils.timezone import is_aware, make_naive

import django_tables2 as tables

from accounts.models import SciriusUser
from rules.models.misc import get_system_settings


def build_path_info(request):
    splval = request.path_info.strip('/ ').split('/')
    if splval[0] == 'rules':
        try:
            splval.remove('pk')
        except ValueError:
            pass
        splval = splval[1:]
    if len(splval):
        return " - ".join(splval)
    return "home"


class TimezoneMiddleware(object):
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            try:
                user = SciriusUser.objects.get(user=request.user)
            except Exception:
                return self.get_response(request)
            if user:
                timezone.activate(user.timezone)
        return self.get_response(request)


class CustomCSPMiddleware(object):
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        splitted_path = list(filter(str.strip, request.path.split('/')))
        if len(splitted_path) > 0:
            if splitted_path[0] in ['rules', 'appliances', 'volumetry', 'viz', 'suricata']:
                response._csp_update = {'style-src': "'unsafe-inline'", 'script-src': "'unsafe-inline'"}
            elif splitted_path[0] == 'accounts':
                if len(splitted_path) > 1 and splitted_path[1] == "login":
                    response._csp_update = {'script-src': "'none'"}
                else:
                    response._csp_update = {'style-src': "'unsafe-inline'", 'script-src': "'unsafe-inline'"}
            elif splitted_path[0] == 'saml2' and splitted_path[1] == 'login':
                if get_middleware_module('common').has_saml_auth():
                    response._csp_update = {'form-action': get_middleware_module('common').saml_idp_hostname(), 'script-src': "'unsafe-inline'"}

        return response


def complete_context(request, context):
    if request.GET.__contains__('duration'):
        duration = int(request.GET.get('duration', '24'))
        if duration > 24 * 30:
            duration = 24 * 30
        request.session['duration'] = duration
    else:
        duration = int(request.session.get('duration', '24'))

    from_date = int((time() - (duration * 3600)) * 1000)
    if duration <= 24:
        date = '%ih' % int(duration)
    else:
        date = '%id' % int(duration / 24)

    context['draw_func'] = 'draw_sunburst'
    context['draw_elt'] = 'path'

    context['date'] = date
    context['from_date'] = from_date
    context['time_range'] = duration * 3600


def scirius_render(request, template, context):
    context['generator'] = settings.RULESET_MIDDLEWARE
    context['path_info'] = build_path_info(request)
    context['scirius_release'] = settings.APP_LONG_NAME + " v" + settings.SCIRIUS_VERSION
    context['app_mngt_name'] = settings.APP_MNGT_NAME
    context['scirius_title'] = get_middleware_module('common').get_homepage_context()['title']
    context['scirius_short_title'] = get_middleware_module('common').get_homepage_context()['short_title']
    context['common_long_name'] = get_middleware_module('common').get_homepage_context()['common_long_name']
    context['product_long_name'] = get_middleware_module('common').get_homepage_context()['product_long_name']
    context['use_stamuslogger'] = get_middleware_module('common').use_stamuslogger()
    gsettings = get_system_settings()
    if settings.USE_SURICATA_STATS:
        context['suricata_stats'] = 1
    if settings.USE_LOGSTASH_STATS:
        context['logstash_stats'] = 1
    if settings.HAVE_NETINFO_AGG:
        context['netinfo_agg'] = 1

    context['elasticsearch'] = 1
    context['custom_elasticsearch'] = gsettings.custom_elasticsearch
    if settings.USE_KIBANA:
        context['kibana'] = 1
        if settings.KIBANA_PROXY:
            context['kibana_url'] = "/kibana"
        else:
            context['kibana_url'] = settings.KIBANA_URL

    if settings.USE_EVEBOX:
        context['evebox'] = 1
        context['evebox_url'] = "/evebox"
    if settings.USE_CYBERCHEF:
        context['cyberchef'] = 1
        context['cyberchef_url'] = "/static/cyberchef/"
    if settings.SCIRIUS_HAS_DOC:
        djurl = request.resolver_match
        context['help_link'] = help_links(djurl.view_name)

    context['toplinks'] = [{
        'id': 'suricata',
        'url': '/suricata/',
        'icon': 'eye-open',
        'label': 'Suricata',
        'perm': request.user.has_perm('rules.configuration_view')
    }]
    context['monitoring_url'] = 'suricata_index'

    extra_context = get_middleware_module('common').update_context(request)
    if 'license' in context:
        extra_context.pop('license', None)
    context.update(extra_context)
    context['messages'] = messages.get_messages(request)
    context['settings'] = settings
    complete_context(request, context)
    return render(request, template, context)


def scirius_listing(request, objectname, assocfn, template='rules/object_list.html', table=None, adduri=None):
    # FIXME could be improved by generating function name

    name = list(assocfn.keys())[0]
    if name == 'Roles' and get_middleware_module('common').has_ldap_auth():
        assocfn['Roles']['action_links']['edit_priorities'] = 'Edit priorities'

    action = name
    if not isinstance(objectname, QuerySet):
        action = objectname.__name__.lower() if name != 'Roles' else 'role'
        olist = objectname.objects.all()
    else:
        olist = objectname

    if name in assocfn:
        if 'annotate' in assocfn[name]:
            olist = olist.annotate(**assocfn[name]['annotate'])
        if 'order_by' in assocfn[name]:
            olist = olist.order_by(*assocfn[name]['order_by'])

    links = assocfn.get(name, {}).get('manage_links', {})
    action_links = assocfn.get(name, {}).get('action_links', {})

    if olist:
        if table is None:
            data = assocfn[name]['table'](olist)
        else:
            data = table(olist)
        tables.RequestConfig(request).configure(data)
    else:
        data = None

    context = {
        'objects': data,
        'size': olist.count(),
        'name': name,
        'manage_links': links,
        'action_links': action_links,
        'action': action,
        'adduri': adduri
    }

    return scirius_render(request, template, context)


def get_middleware_module(module):
    return import_module('%s.%s' % (settings.RULESET_MIDDLEWARE, module))


def help_links(djlink):
    HELP_LINKS_TABLE = {
        "sources": {"name": "Creating a source", "base_url": "doc/ruleset.html", "anchor": "#creating-source"},
        "add_source": {"name": "Add a custom source", "base_url": "doc/ruleset.html", "anchor": "#manual-addition"},
        "add_public_source": {"name": "Add a public source", "base_url": "doc/ruleset.html", "anchor": "#public-sources"},
        "threshold_rule": {"name": "Suppression and thresholding", "base_url": "doc/ruleset.html", "anchor": "#suppression-and-thresholding"},
        "add_ruleset": {"name": "Ruleset creation", "base_url": "doc/ruleset.html", "anchor": "#creating-ruleset"},
        "edit_ruleset": {"name": "Edit Ruleset", "base_url": "doc/ruleset.html", "anchor": "#editing-ruleset"},
        "edit_rule": {"name": "Transform Rule", "base_url": "doc/ruleset.html", "anchor": "#rule-transformations"},
        "accounts_manage": {"name": "Accounts Management", "base_url": "doc/local-user-management.html", "anchor": "#manage-accounts"},
    }
    Probe = __import__(settings.RULESET_MIDDLEWARE)
    help_link = Probe.common.help_links(djlink)
    return help_link if help_link else HELP_LINKS_TABLE.get(djlink)


def convert_datetime_to_timestamp(dt: datetime.datetime, in_ms: bool = False) -> int:
    """
    Convert a datetime object to timestamps (second or milliseconds)
    Convertit un objet datetime en un timestamp (secondes ou millisecondes).

    Args:
        dt (datetime.datetime): datetime object to convert

        in_ms (bool): true if you want the output in ms

    Returns:
        int: timestamp
    """
    timestamp_seconds = int(dt.timestamp())

    if in_ms:
        return timestamp_seconds * 1000
    return timestamp_seconds


# Based on https://github.com/jieter/django-tables2/blob/master/CHANGELOG.md#breaking-changes-200
class SciriusTable(tables.Table):
    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop('request', None)
        super().__init__(*args, **kwargs)

    def get_column_class_names(self, classes_set, bound_column):
        classes_set = super(SciriusTable, self).get_column_class_names(classes_set, bound_column)
        classes_set.add(bound_column.name)
        return classes_set


# https://stackoverflow.com/questions/20656135/python-deep-merge-dictionary-data
def merge_dict_deeply(src, dest):
    for key, value in list(src.items()):
        if isinstance(value, dict):
            node = dest.setdefault(key, {})
            merge_dict_deeply(value, node)
        else:
            dest[key] = value
    return dest


def read_in_chunks(file_, chunk_size: int = 1024):
    while True:
        data = file_.read(chunk_size)
        if not data:
            break
        yield data


class RequestsWrapper:
    def __init__(self, verify: bool = True, use_proxy: bool = True):
        self._verify = verify
        self.use_proxy = use_proxy

    def _initialize_client(self, use_proxy: bool, scheme: str = "https") -> httpx.Client:
        """
        Initialize HTTPX client with all the related configuraation
        """
        client_kwargs: dict[str, Any] = {
            'timeout': 30,
            'verify': self._verify,
            'headers': self._get_default_headers()
        }

        if use_proxy:
            proxy = self._get_proxy(scheme)
            if proxy:
                client_kwargs['proxy'] = proxy

        return httpx.Client(**client_kwargs)

    def _get_default_headers(self) -> dict[str, str]:
        agent = f'scirius/{settings.SCIRIUS_VERSION}'
        seed = os.getenv('STAMUSCTL_SEED')
        if seed:
            seed = seed.strip().strip('"')
            agent = f'scirius/{settings.SCIRIUS_VERSION} ({seed})'
        return {'User-Agent': agent}

    def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """
        Perform the HTTP request and manage errors.
        """
        client = self._initialize_client(self.use_proxy, url.split("://")[0])

        try:
            resp = client.request(method, url, **kwargs)
            resp.raise_for_status()
            return resp

        except httpx.ConnectError as exc:
            exc_str = str(exc)
            if "Name or service not known" in exc_str:
                raise OSError("Connection error 'Name or service not known'")
            if "Connection timed out" in exc_str:
                raise OSError("Connection error 'Connection timed out'")
            raise OSError(f"Connection error '{exc}'")

        except httpx.TimeoutException:
            raise OSError("Request timeout, server may be down")

        except httpx.TooManyRedirects:
            raise OSError("Too many redirects, server may be broken")

        except httpx.HTTPError as exc:
            # Centralize HTTP errors management
            if hasattr(exc, 'response') and exc.response.status_code == 404:
                raise OSError("URL not found on server (error 404), please check URL")
            if hasattr(exc, 'response'):
                raise OSError(f"HTTP error {exc.response.status_code} sent by server, please check URL or server")
            # HTTP error without response (ex: redirect before response)
            raise OSError(f"An unspecified HTTP error occurred: {exc}")
        finally:
            client.close()

    @staticmethod
    def _get_proxy(scheme: str = "https") -> httpx.Proxy | None:
        """
        Get proxy if applicable depending on the scheme given by the target URL

        We cannot use mounts parameter in HTTPX client because it uses httpx.HTTPTransport and we cannot set the full
        ssl_context (see httpx sources)
        """
        if proxy_params := get_system_settings().get_proxy_params():
            ssl_context = None
            if not proxy_params["verify"]:
                # create an SSL context that trusts EVERYTHING (Insecure)
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE  # noqa: DUO122
            return httpx.Proxy(proxy_params[scheme], ssl_context=ssl_context)
        return None

    def head(self, url: str, **kwargs) -> httpx.Response:
        return self.request("HEAD", url, **kwargs)

    def connect(self, url: str, **kwargs) -> httpx.Response:
        return self.request("CONNECT", url, **kwargs)

    def options(self, url: str, **kwargs) -> httpx.Response:
        return self.request("OPTIONS", url, **kwargs)

    def trace(self, url: str, **kwargs) -> httpx.Response:
        return self.request("TRACE", url, **kwargs)

    def get(self, url: str, **kwargs) -> httpx.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> httpx.Response:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs) -> httpx.Response:
        return self.request("PUT", url, **kwargs)

    def patch(self, url: str, **kwargs) -> httpx.Response:
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs) -> httpx.Response:
        return self.request("DELETE", url, **kwargs)


def convert_to_utc(time, user):
    try:
        tz = pytz.timezone(user.sciriususer.timezone)
    except Exception:
        return time
    return tz.normalize(tz.localize(time.replace(tzinfo=None))).astimezone(pytz.utc)


def convert_to_local(time, user):
    try:
        tz = pytz.timezone(user.sciriususer.timezone)
    except Exception:
        return time
    return pytz.utc.normalize(pytz.utc.localize(time.replace(tzinfo=None))).astimezone(tz)


def sizeof_fmt(num: float) -> str:
    """
    Utility function to convert bytes to a more readable format.
    """
    for unit in ("", "K", "M", "G", "T", "P", "E", "Z"):
        if abs(num) < 1024.0:
            return f"{num:3.1f} {unit}B"
        num /= 1024.0
    return f"{num:.1f} YB"


def get_folder_size(folder):
    # based on: https://stackoverflow.com/a/55659577
    return sum(file.stat().st_size for file in Path(folder).rglob('*'))


def is_ajax(request):
    return request.headers.get('x-requested-with') == 'XMLHttpRequest'


class ExtendedJSONEncoder(json.JSONEncoder):
    """Custom JSONEncoder that handles datetime objects."""

    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            # Convert datetime object to ISO 8601 string
            if is_aware(obj):
                obj = make_naive(obj)
            return obj.isoformat()
        # default behaviour for remaining stuff
        return super().default(obj)


class ExtendedJSONSerializer(DjangoJSONSerializer):
    """
    Extended JSONSerializer that uses a custom encoder to handle datetime objects.
    """

    def dumps(self, obj):
        return json.dumps(obj, separators=(",", ":"), cls=ExtendedJSONEncoder).encode("latin-1")
