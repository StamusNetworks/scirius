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


from django.urls import path
from django.urls import re_path

from accounts import views

urlpatterns = [
    path('', views.list_accounts, name='list_accounts'),
    path('logout/', views.logoutview, name='accounts_logout'),
    re_path(r'^login/(?P<target>.*)$', views.loginview, name='accounts_login'),
    path('user/', views.list_users, name='list_users'),
    path('user/add/', views.add_user, name='add_user'),
    path('user/<int:user_id>/', views.edit_user, name='edit_user'),
    path('user/<int:user_id>/delete/', views.delete_user, name='delete_user'),
    path('user/<int:user_id>/edit_password/', views.edit_password, name='edit_password'),
    path('role/', views.list_groups, name='list_groups'),
    path('role/add/', views.add_group, name='add_group'),
    path('role/<int:group_id>/', views.edit_group, name='edit_group'),
    path('role/<int:group_id>/delete/', views.delete_group, name='delete_group'),
    path('priorities/', views.edit_priorities, name='edit_priorities'),
    path('sort_priorities/', views.sort_priorities, name='sort_priorities'),
    path('current_user/', views.current_user, name='current_user'),
    path('token_list/', views.token_list, name='token_list'),
    path('token_add/', views.token_add, name='token_add'),
    path('token_edit/<int:user_id>/', views.token_edit, name='token_edit'),
    path('token_delete/<int:user_id>/', views.token_delete, name='token_delete'),

    # TODO PERMS: split into different views
    re_path(r'^edit/(?P<action>.*)$', views.editview, name='accounts_edit'),
]
