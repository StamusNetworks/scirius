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

from django.conf.urls import patterns, url

from suricata import views

urlpatterns = patterns('',
    url(r'^$', views.index, name='suricata_index'),
    url(r'^edit$', views.edit, name='suricata_edit'),
    url(r'^update$', views.update, name='suricata_update'),
    url(r'^dashboard$', views.dashboard, name='suricata_dashboard'),
    )
