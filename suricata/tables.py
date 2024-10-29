"""
Copyright(C) 2024, Stamus Networks
Written by Nicolas Frisoni <nfrisoni@stamus-networks.com>

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

import json
from suricata.models import RecurrentTask
from scirius.utils import SciriusTable
from rules.tables import DefaultMeta

from django.utils.html import format_html
import django_tables2 as tables


class RecurrentTaskTable(SciriusTable):
    id = tables.LinkColumn('scheduledtask', args=[tables.A('pk')])
    name = tables.Column(accessor='id', verbose_name='Name')

    def render_name(self, record):
        return record.get_task()._display_title()

    def render_task_options(self, record):
        options = json.loads(record.task_options)
        options.pop('overrided_params', None)
        trs = ''.join([f'<tr><td>{k}</td><td>{v}</td></tr>' for k, v in options.items()])
        table = f'<table>{trs}</table>'
        return format_html(table)

    class Meta(DefaultMeta):
        model = RecurrentTask
        fields = ('id', 'name', 'task_options', 'created', 'scheduled', 'fired', 'recurrence')
