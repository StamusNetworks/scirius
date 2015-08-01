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
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_SERVERS: "$HOME_NET"
    SMTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"
    TELNET_SERVERS: "$HOME_NET"
    AIM_SERVERS: "$EXTERNAL_NET"
    DNP3_SERVER: "$HOME_NET"
    DNP3_CLIENT: "$HOME_NET"
    MODBUS_CLIENT: "$HOME_NET"
    MODBUS_SERVER: "$HOME_NET"
    ENIP_CLIENT: "$HOME_NET"
    ENIP_SERVER: "$HOME_NET"
  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502
"""

    REFERENCE_CONFIG = """
# config reference: system URL

config reference: bugtraq   http://www.securityfocus.com/bid/
config reference: bid	    http://www.securityfocus.com/bid/
config reference: cve       http://cve.mitre.org/cgi-bin/cvename.cgi?name=
#config reference: cve       http://cvedetails.com/cve/
config reference: secunia   http://www.secunia.com/advisories/

#whitehats is unfortunately gone
config reference: arachNIDS http://www.whitehats.com/info/IDS

config reference: McAfee    http://vil.nai.com/vil/content/v_
config reference: nessus    http://cgi.nessus.org/plugins/dump.php3?id=
config reference: url       http://
config reference: et        http://doc.emergingthreats.net/
config reference: etpro     http://doc.emergingthreatspro.com/
config reference: telus     http://
config reference: osvdb     http://osvdb.org/show/osvdb/
config reference: threatexpert http://www.threatexpert.com/report.aspx?md5=
config reference: md5	    http://www.threatexpert.com/report.aspx?md5=
config reference: exploitdb http://www.exploit-db.com/exploits/
config reference: openpacket https://www.openpacket.org/capture/grab/
config reference: securitytracker http://securitytracker.com/id?
config reference: secunia   http://secunia.com/advisories/
config reference: xforce    http://xforce.iss.net/xforce/xfdb/
config reference: msft      http://technet.microsoft.com/security/bulletin/
"""

    CLASSIFICATION_CONFIG = """
config classification: not-suspicious,Not Suspicious Traffic,3
config classification: unknown,Unknown Traffic,3
config classification: bad-unknown,Potentially Bad Traffic, 2
config classification: attempted-recon,Attempted Information Leak,2
config classification: successful-recon-limited,Information Leak,2
config classification: successful-recon-largescale,Large Scale Information Leak,2
config classification: attempted-dos,Attempted Denial of Service,2
config classification: successful-dos,Denial of Service,2
config classification: attempted-user,Attempted User Privilege Gain,1
config classification: unsuccessful-user,Unsuccessful User Privilege Gain,1
config classification: successful-user,Successful User Privilege Gain,1
config classification: attempted-admin,Attempted Administrator Privilege Gain,1
config classification: successful-admin,Successful Administrator Privilege Gain,1


# NEW CLASSIFICATIONS
config classification: rpc-portmap-decode,Decode of an RPC Query,2
config classification: shellcode-detect,Executable code was detected,1
config classification: string-detect,A suspicious string was detected,3
config classification: suspicious-filename-detect,A suspicious filename was detected,2
config classification: suspicious-login,An attempted login using a suspicious username was detected,2
config classification: system-call-detect,A system call was detected,2
config classification: tcp-connection,A TCP connection was detected,4
config classification: trojan-activity,A Network Trojan was detected, 1
config classification: unusual-client-port-connection,A client was using an unusual port,2
config classification: network-scan,Detection of a Network Scan,3
config classification: denial-of-service,Detection of a Denial of Service Attack,2
config classification: non-standard-protocol,Detection of a non-standard protocol or event,2
config classification: protocol-command-decode,Generic Protocol Command Decode,3
config classification: web-application-activity,access to a potentially vulnerable web application,2
config classification: web-application-attack,Web Application Attack,1
config classification: misc-activity,Misc activity,3
config classification: misc-attack,Misc Attack,2
config classification: icmp-event,Generic ICMP event,3
config classification: kickass-porn,SCORE! Get the lotion!,1
config classification: policy-violation,Potential Corporate Privacy Violation,1
config classification: default-login-attempt,Attempt to login by a default username and password,2
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

    def rule_buffer(self, rule_buffer, config_buffer = None, related_files = {}, reference_config = None, classification_config = None):
        # create temp directory
        tmpdir = tempfile.mkdtemp()
        # write the rule file in temp dir
        rule_file = os.path.join(tmpdir, "file.rules")
        rf = open(rule_file, 'w')
        # write the config file in temp dir
        rf.write(rule_buffer)
        rf.close()

        if not reference_config:
            refence_config = self.REFERENCE_CONFIG
        reference_file = os.path.join(tmpdir, "reference.config")
        rf = open(reference_file, 'w')
        rf.write(refence_config)
        rf.close()

        if not classification_config:
            classification_config = self.CLASSIFICATION_CONFIG
        classification_file = os.path.join(tmpdir, "classification.config")
        cf = open(classification_file, 'w')
        cf.write(classification_config)
        cf.close()

        if not config_buffer:
            config_buffer = self.CONFIG_FILE
        config_file = os.path.join(tmpdir, "suricata.yaml")
        cf = open(config_file, 'w')
        # write the config file in temp dir
        cf.write(config_buffer)
        cf.write("default-rule-path: " + tmpdir + "\n")
        cf.write("default-reputation-path: " + tmpdir + "\n")
        cf.write("reference-config-file: " + tmpdir + "/reference.config\n")
        cf.write("classification-file: " + tmpdir + "/classification.config\n")
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
