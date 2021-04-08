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


from django.conf.urls import url

from accounts import views

urlpatterns = [
    url(r'^$', views.list_accounts, name='list_accounts'),
    url(r'^logout/$', views.logoutview, name='accounts_logout'),
    url(r'^login/(?P<target>.*)$', views.loginview, name='accounts_login'),
    url(r'^user/$', views.list_users, name='list_users'),
    url(r'^user/add/$', views.add_user, name='add_user'),
    url(r'^user/(?P<user_id>\d+)$', views.edit_user, name='edit_user'),
    url(r'^user/(?P<user_id>\d+)/delete$', views.delete_user, name='delete_user'),
    url(r'^user/(?P<user_id>\d+)/edit_password$', views.edit_password, name='edit_password'),
    url(r'^role/$', views.list_groups, name='list_groups'),
    url(r'^role/add/$', views.add_group, name='add_group'),
    url(r'^role/(?P<group_id>\d+)$', views.edit_group, name='edit_group'),
    url(r'^role/(?P<group_id>\d+)/delete$', views.delete_group, name='delete_group'),
    url(r'^priorities/$', views.edit_priorities, name='edit_priorities'),
    url(r'^sort_priorities/$', views.sort_priorities, name='sort_priorities'),
    url(r'^current_user/$', views.current_user, name='current_user'),

    # TODO PERMS: split into different views
    url(r'^edit/(?P<action>.*)$', views.editview, name='accounts_edit'),
]
