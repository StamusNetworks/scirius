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


import re
import IPy

from django.core.exceptions import ValidationError


def no_space_validator(value):
    if ' ' in value:
        raise ValidationError('"%s" contains space' % value)


def validate_hostname(value):
    no_space_validator(value)
    if '_' in value:
        raise ValidationError('"%s" contains underscore' % value)

    # http://www.regextester.com/23
    HOSTNAME_RX = r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$'

    if re.match(HOSTNAME_RX, value):
        return
    raise ValidationError(f'"{value}": Invalid hostname', code='invalid_hostname')


def validate_dns(value):
    if ' ' in value:
        raise ValidationError('"%s" contains space' % value)

    # based on http://www.regextester.com/23 + '_'
    HOSTNAME_RX = r'^(([a-zA-Z0-9_]|[a-zA-Z0-9_][a-zA-Z0-9\-_]*[a-zA-Z0-9_])\.)*([A-Za-z0-9_]|[A-Za-z0-9_][A-Za-z0-9\-_]*[A-Za-z0-9_])$'

    if re.match(HOSTNAME_RX, value):
        return
    raise ValidationError('Invalid hostname', code='invalid_hostname')


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
