"""
Copyright(C) 2014, 2015 Stamus Networks
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

#from django.template import Context, Template
from django.conf import settings
from influxdb import InfluxDBClient

def influx_get_timeline(time_range, request="eve_rate"):
    result = None
    client = InfluxDBClient(settings.INFLUXDB_HOST, settings.INFLUXDB_PORT,
                            settings.INFLUXDB_USER, settings.INFLUXDB_PASSWORD,
                            settings.INFLUXDB_DATABASE)
    if request == "eve_rate":
        result = client.query("select mean(value) from /eve.*.rate_1m/ where time > now()-%ds group by time(%ds) fill(0) order asc"  % (time_range, time_range / 120))
    elif request == "suri_packet":
        result = client.query("select derivative(value) from /suricata.*.capture.kernel_packets/ where time > now()-%ds group by time(%ds) fill(0) order asc" % (time_range, time_range / 120))
    elif request == "suri_drop":
        result = client.query("select derivative(value) from /suricata.*.capture.kernel_drops/ where time > now()-%ds group by time(%ds) fill(0) order asc" % (time_range, time_range / 120))
    # speed is always positive so set to 0 if negative (which is mostly due to restart of stats)
    for line in result:
        line['points'] = [[pt[0], max(pt[1], 0)] for pt in line['points']]
    return result
