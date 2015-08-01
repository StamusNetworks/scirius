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

class Info():
    def status(self):
        suri_running = False
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

class Test():
    RULEFILE_ERRNO = [ 39, 42 ]
    USELESS_ERRNO = [ 40, 43, 44 ]
    CONFIG_FILE = """
%YAML 1.1
---
logging:
  default-log-level: error
  outputs:
  - console:
      enabled: yes
      type: json
"""

    def parse_suricata_error(self, error, single = False):
        error_list = []
        error_stream = StringIO.StringIO(error)
        for line in error_stream:
            try:
                s_err = json.loads(line)
            except:
                return {'message': error}
            errno = s_err['engine']['error_code']
            if not single or errno not in self.RULEFILE_ERRNO:
                if not errno in self.USELESS_ERRNO:
                    # clean error message
                    if errno == 39:
                        s_err['engine']['message'] = s_err['engine']['message'].split(' from file')[0] 
                        getsid = re.compile("sid *:(\d+)")
                        match = getsid.search(line)
                        if match:
                            s_err['engine']['sid'] = match.groups()[0]
                    error_list.append(s_err['engine'])
        return error_list

    def rule_buffer(self, rule_buffer, config_buffer = None, related_files = {}):
        # create temp directory
        tmpdir = tempfile.mkdtemp()
        # write the rule file in temp dir
        rule_file = os.path.join(tmpdir, "file.rules")
        rf = open(rule_file, 'w')
        # write the config file in temp dir
        rf.write(rule_buffer)
        rf.close()

        if not config_buffer:
            config_buffer = self.CONFIG_FILE
        config_file = os.path.join(tmpdir, "suricata.yaml")
        cf = open(config_file, 'w')
        # write the config file in temp dir
        cf.write(config_buffer)
        cf.write("default-rule-path: " + tmpdir + "\n")
        cf.write("default-reputation-path: " + tmpdir + "\n")
        cf.close()
        for rfile in related_files:
            related_file = os.path.join(tmpdir, rfile)
            rf = open(related_file, 'w')
            rf.write(related_files[rfile])
            rf.close()
            
        suri_cmd = ['suricata', '-T', '-l', tmpdir, '-S', rule_file, '-c', config_file]
        # start suricata in test mode
        suriprocess = subprocess.Popen(suri_cmd , stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (outdata, errdata) = suriprocess.communicate()
        shutil.rmtree(tmpdir)
        # if success ok
        if suriprocess.returncode == 0:
            return {'status': True}
        # if not return error
        return {'status': False, 'errors': errdata}

    def rule(self, rule_buffer, config_buffer = None, related_files = {}):
        prov_result = self.rule_buffer(rule_buffer, config_buffer = config_buffer, related_files = related_files)
        if prov_result['status']:
            return prov_result
        prov_result['errors'] = self.parse_suricata_error(prov_result['errors'], single = True)
        return prov_result

    def rules(self, rule_buffer, config_buffer = None, related_files = {}):
        prov_result = self.rule_buffer(rule_buffer, config_buffer = config_buffer, related_files = related_files)
        if prov_result['status']:
            return prov_result
        prov_result['errors'] = self.parse_suricata_error(prov_result['errors'], single = False)
        return prov_result

#buf = """
#alert modbus any any -> any any (msg:"SURICATA Modbus invalid Protocol version"; app-layer-event:modbus.invalid_protocol_id; sid:2250001; rev:1;)
#alert modbus any any -> any any (msg:"SURICATA Modbus invalid Protocol version"; app-layer-event:modbus.invalid_protocol_id; sid:2250002; rev:1;)
#alert tls any any -> any any (msg:"SURICATA TLS Self Signed Certificate"; flow:established; luajit:self-signed-cert.lua; tls.store; classtype:protocol-command-decode; sid:999666111; rev:1;)
#"""
#
#test = Test()
#result = test.rules(buf)
#if not result['status']:
#    print json.dumps(result['error'])
