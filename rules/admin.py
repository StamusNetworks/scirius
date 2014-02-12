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

from django.contrib import admin

# Register your models here.
from rules.models import Source
from rules.models import Ruleset
from rules.models import Category
from rules.models import Rule
from rules.models import Reference

admin.site.register(Source)
admin.site.register(Ruleset)
admin.site.register(Category)
admin.site.register(Rule)
admin.site.register(Reference)
