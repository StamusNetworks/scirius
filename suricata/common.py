"""
Copyright(C) 2015, Stamus Networks
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

import psutil
import subprocess
import tempfile
import shutil
import os
import json
import StringIO
import re

from django.conf import settings

if settings.SURICATA_UNIX_SOCKET:
    try:
        import suricatasc
    except:
        settings.SURICATA_UNIX_SOCKET = None

class Info():
    def status(self):
        suri_running = False
        if settings.SURICATA_UNIX_SOCKET:
            sc = suricatasc.SuricataSC(settings.SURICATA_UNIX_SOCKET)
            try:
                sc.connect()
            except:
                return False
            res = sc.send_command('uptime', None)
            if res['return'] == 'OK':
                suri_running = True
            sc.close()
        else:
            for proc in psutil.process_iter():
                try:
                    pinfo = proc.as_dict(attrs=['name'])
                except psutil.NoSuchProcess:
                    pass
                else:
                    if pinfo['name'] == 'Suricata-Main':
                        suri_running = True
                        break
        return suri_running
    def disk(self):
        return psutil.disk_usage('/')
    def memory(self):
        return psutil.virtual_memory()
    def cpu(self):
        return psutil.cpu_percent(interval=0.2)

def get_es_template():
    return 'rules/elasticsearch.html'

def help_links(djlink):
    HELP_LINKS_TABLE = {
        "suricata_edit": {"name": "Suricata setup", "base_url": "doc/suricata-ce.html", "anchor": "#setup" },
        "suricata_update": {"name": "Updating Suricata ruleset", "base_url": "doc/suricata-ce.html", "anchor": "#updating-ruleset" },
        }
    if HELP_LINKS_TABLE.has_key(djlink):
        return HELP_LINKS_TABLE[djlink]
    return None
