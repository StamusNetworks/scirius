"""
Copyright(C) 2014-2019 Stamus Networks
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

from __future__ import unicode_literals
import IPy

from django.core.exceptions import ValidationError


def validate_addresses_or_networks(value):
    try:
        for val in value.split(','):
            validate_address_or_network(val)
    except ValidationError:
        raise ValidationError('"%s" should be a valid list of comma separated ip addresses or networks addresses' % value)


def validate_address_or_network(value):
    try:
        IPy.IP(value)
    except ValueError:
        raise ValidationError('"%s" is not a valid ip address or network address' % value)
