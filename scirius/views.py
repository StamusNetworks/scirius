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

from django.shortcuts import redirect
from django.contrib.auth import authenticate, login, logout
from django.conf import settings

from utils import scirius_render
from forms import LoginForm

from revproxy.views import ProxyView

def homepage(request):
    return redirect("rules/")


def scirius_login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(username=username, password=password)
        if user is not None:
            if user.is_active:
                login(request, user)
                # FIXME Redirect to wanted page
                return redirect("/rules/")
            else:
                form = LoginForm()
                context = { 'form': form, 'error': 'Disabled account' }
                return scirius_render(request, 'rules/login.html', context)
        else:
            form = LoginForm()
            context = { 'form': form, 'error': 'Invalid login' }
            return scirius_render(request, 'rules/login.html', context)
    else:
        form = LoginForm()
        context = { 'form': form }
        return scirius_render(request, 'rules/login.html', context);


def scirius_logout(request):
    logout(request)
    return redirect("/login/")

# Proxy
class KibanaProxyView(ProxyView):
    upstream = settings.KIBANA_URL
    add_remote_user = False

class ElasticsearchProxyView(ProxyView):
    upstream = "http://" + settings.ELASTICSEARCH_ADDRESS
    add_remote_user = False
