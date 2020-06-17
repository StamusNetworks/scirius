"""
Copyright(C) 2018-2020 Stamus Networks
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

from __future__ import unicode_literals
import subprocess
import tempfile
import shutil
import os
import json
import StringIO
import re

from django.utils.html import escape
from django.conf import settings


class TestRules():
    VARIABLE_ERROR = 101
    OPENING_RULE_FILE = 41  # Error when opening a file referenced in the source
    RULEFILE_ERRNO = [39, 42]
    USELESS_ERRNO = [40, 43, 44]
    CONFIG_FILE = """
%YAML 1.1
---
logging:
  default-log-level: error
  outputs:
  - console:
      enabled: yes
      type: json
app-layer:
  protocols:
    tls:
      ja3-fingerprints: yes
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
    FILE_DATA_PORTS: "[$HTTP_PORTS,110,143]"
    FTP_PORTS: 21
    VXLAN_PORTS: 4789
    TEREDO_PORTS: 3544
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

config classification: targeted-activity,Targeted Malicious Activity was Detected,1
config classification: exploit-kit,Exploit Kit Activity Detected,1
config classification: external-ip-check,Device Retrieving External IP Address Detected,2
config classification: domain-c2,Domain Observed Used for C2 Detected,1
config classification: pup-activity,Possibly Unwanted Program Detected,2
config classification: credential-theft,Successful Credential Theft Detected,1
config classification: social-engineering,Possible Social Engineering Attempted,2
config classification: coin-mining,Crypto Currency Mining Activity Detected,2
config classification: command-and-control,Malware Command and Control Activity Detected,1
"""

    def parse_suricata_error(self, error, single=False):
        ret = {
            'errors': [],
            'warnings': [],
        }
        variable_list = []
        files_list = []
        error_stream = StringIO.StringIO(error)
        for line in error_stream:
            try:
                s_err = json.loads(line)
            except Exception:
                ret['errors'].append({'message': error, 'format': 'raw'})
                return ret
            errno = s_err['engine']['error_code']
            if not single or errno not in self.RULEFILE_ERRNO:
                if errno == self.VARIABLE_ERROR:
                    variable = s_err['engine']['message'].split("\"")[1]
                    if not "$" + variable in variable_list:
                        variable_list.append("$" + variable)
                        s_err['engine']['message'] = "Custom address variable \"$%s\" is used and need to be defined in probes configuration" % (variable)
                        ret['warnings'].append(s_err['engine'])
                    continue
                if errno == self.OPENING_RULE_FILE:
                    m = re.match('opening hash file ([^:]*): No such file or directory', s_err['engine']['message'])
                    if m is not None:
                        filename = m.group(1)
                        filename = filename.rsplit('/', 1)[1]
                        files_list.append(filename)
                        s_err['engine']['message'] = 'External file "%s" is a dependancy and needs to be added to rulesets' % filename
                        ret['warnings'].append(s_err['engine'])
                        continue
                if errno not in self.USELESS_ERRNO:
                    # clean error message
                    if errno == 39:
                        # exclude error on variable
                        found = False
                        for variable in variable_list:
                            if variable in s_err['engine']['message']:
                                found = True
                                break
                        else:
                            # exclude error on external file
                            for filename in files_list:
                                if re.search(': *%s *;' % filename, s_err['engine']['message']):
                                    found = True
                                    break
                        if found:
                            continue
                        s_err['engine']['message'] = s_err['engine']['message'].split(' from file')[0]
                        getsid = re.compile("sid *:(\d+)")
                        match = getsid.search(line)
                        if match:
                            s_err['engine']['sid'] = int(match.groups()[0])
                    if errno == 42:
                        s_err['engine']['message'] = s_err['engine']['message'].split(' from')[0]
                    ret['errors'].append(s_err['engine'])
        return ret

    def rule_buffer(self, rule_buffer, config_buffer=None, related_files=None, reference_config=None, classification_config=None, cats_content='', iprep_content=''):
        # create temp directory
        tmpdir = tempfile.mkdtemp()
        # write the rule file in temp dir
        rule_file = os.path.join(tmpdir, "file.rules")
        rf = open(rule_file, 'w')
        try:
            rf.write(rule_buffer)
        except UnicodeEncodeError:
            rf.write(rule_buffer.encode('utf-8'))
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
        cf.write("mpm-algo: ac-bs\n")
        cf.write("default-rule-path: " + tmpdir + "\n")
        cf.write("reference-config-file: " + tmpdir + "/reference.config\n")
        cf.write("classification-file: " + tmpdir + "/classification.config\n")
        cf.write("reputation-categories-file: " + tmpdir + "/scirius-categories.txt\n")
        cf.write("default-reputation-path: " + tmpdir + "\n")
        cf.write("""reputation-files:
  - scirius-iprep.list
""")

        cf.close()
        related_files = related_files or {}
        for rfile in related_files:
            related_file = os.path.join(tmpdir, rfile)
            rf = open(related_file, 'w')
            rf.write(related_files[rfile])
            rf.close()

        from rules.models import export_iprep_files
        export_iprep_files(tmpdir, cats_content, iprep_content)

        suri_cmd = [settings.SURICATA_BINARY, '-T', '-l', tmpdir, '-S', rule_file, '-c', config_file]
        # start suricata in test mode
        suriprocess = subprocess.Popen(suri_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (outdata, errdata) = suriprocess.communicate()
        shutil.rmtree(tmpdir)
        # if success ok
        if suriprocess.returncode == 0:
            return {'status': True, 'errors': ''}
        # if not return error
        return {'status': False, 'errors': errdata}

    def _escape_result(self, res):
        for key in ('warnings', 'errors'):
            lst = res.get(key, [])
            for msg in lst:
                msg['message'] = escape(msg['message'])
        return res

    def check_rule_buffer(self, rule_buffer, config_buffer=None, related_files=None, single=False, cats_content='', iprep_content=''):
        related_files = related_files or {}
        prov_result = self.rule_buffer(rule_buffer, config_buffer=config_buffer, related_files=related_files, cats_content=cats_content, iprep_content=iprep_content)
        if prov_result['status'] and not prov_result.has_key('warnings'):
            return self._escape_result(prov_result)
        res = self.parse_suricata_error(prov_result['errors'], single=single)
        prov_result['errors'] = res['errors']
        prov_result['warnings'] = res['warnings']
        i = 6  # support only 6 unknown variables per rule
        prov_result['iter'] = 0
        while len(res['warnings']) and i > 0:
            modified = False
            for warning in res['warnings']:
                if warning['error_code'] == self.VARIABLE_ERROR:
                    var = warning['message'].split("\"")[1]
                    # transform rule_buffer to remove the faulty variable
                    if not var.endswith('_PORTS') and not var.endswith('_PORT'):
                        rule_buffer = rule_buffer.replace("!" + var, "192.0.2.0/24")
                        rule_buffer = rule_buffer.replace(var, "192.0.2.0/24")
                    else:
                        rule_buffer = rule_buffer.replace("!" + var, "21")
                        rule_buffer = rule_buffer.replace(var, "21")
                    modified = True
            if modified is False:
                break
            result = self.rule_buffer(rule_buffer, config_buffer=config_buffer, related_files=related_files, cats_content=cats_content, iprep_content=iprep_content)
            res = self.parse_suricata_error(result['errors'], single=single)
            prov_result['errors'] = res['errors']
            if len(res['warnings']):
                prov_result['warnings'] = prov_result['warnings'] + res['warnings']
            i = i - 1
            prov_result['iter'] = prov_result['iter'] + 1
        if len(prov_result['errors']) == 0:
            prov_result['status'] = True
        return self._escape_result(prov_result)
