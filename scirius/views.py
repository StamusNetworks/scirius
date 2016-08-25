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

import logging

from django.shortcuts import redirect
from django.conf import settings

from revproxy.views import ProxyView

# Avoid logging every request
revproxy_logger = logging.getLogger('revproxy')
revproxy_logger.setLevel(logging.WARNING)

def homepage(request):
    return redirect("rules/")

# Proxy
class KibanaProxyView(ProxyView):
    upstream = settings.KIBANA_URL
    add_remote_user = False

class EveboxProxyView(ProxyView):
    upstream = "http://" + settings.EVEBOX_ADDRESS
    add_remote_user = True
