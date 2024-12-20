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

from suricatals import LangServer
from suricatals.lsp_helpers import Diagnosis
import tempfile


class TestRules():
    IP_REP_CONF = '''
# IP Reputation
reputation-categories-file: {tmpdir}/scirius-categories.txt
default-reputation-path: {tmpdir}
reputation-files:
 - {tmpdir}/scirius-iprep.list
    '''

    def build_iprep_buffers(self, cats_content, iprep_content):
        from rules.models import Rule

        group_rules = Rule.objects.filter(group=True)
        cat_map = {}
        buffers = {'scirius-categories.txt': '', 'scirius-iprep.list': ''}

        for index, rule in enumerate(group_rules, 1):
            buffers['scirius-categories.txt'] += f'{index},{rule.sid},{rule.msg}\n'
            cat_map[index] = rule
        if cats_content:
            buffers['scirius-categories.txt'] += cats_content

        for cate in cat_map:
            for IP in cat_map[cate].group_ips_list.split(','):
                buffers['scirius-iprep.list'] += f'{IP},{cate},100\n'
        if iprep_content:
            buffers['scirius-iprep.list'] += iprep_content

        return buffers

    def rules_infos(self, rule_buffer, **kwargs):
        extra_buffers = self.build_iprep_buffers(
            kwargs.pop('cats_content', None),
            kwargs.pop('iprep_content', None)
        )
        kwargs['extra_buffers'] = extra_buffers
        testor = LangServer(conn=None)

        return testor.rules_tester.rules_infos(
            rule_buffer,
            **kwargs
        )

    def check_rule_buffer(self, rule_buffer, config_buffer=None, related_files=None, cats_content='', iprep_content='', engine_analysis=False):
        extra_buffers = self.build_iprep_buffers(cats_content, iprep_content)
        testor = LangServer(conn=None)
        params = {
            'config_buffer': config_buffer,
            'related_files': related_files,
            'extra_buffers': extra_buffers
        }

        if extra_buffers:
            params.update({
                'extra_conf': self.IP_REP_CONF
            })

        result = testor.rules_tester.check_rule_buffer(
            rule_buffer,
            engine_analysis=engine_analysis,
            **params
        )

        idx = 6  # support only 6 unknown variables per rule
        r_buffer = None
        while len(result['warnings']) and idx > 0:
            modified = False
            for warning in result['warnings']:
                if warning.get('variable_error', False):
                    var = warning['message'].split("\"")[1]
                    if not var.endswith('_PORTS') and not var.endswith('_PORT'):
                        r_buffer = rule_buffer.replace("!" + var, "192.0.2.0/24")
                        r_buffer = rule_buffer.replace(var, "192.0.2.0/24")
                    else:
                        r_buffer = rule_buffer.replace("!" + var, "21")
                        r_buffer = rule_buffer.replace(var, "21")
                    modified = True

            if modified is False:
                break

            if r_buffer:
                result = testor.rules_tester.check_rule_buffer(
                    r_buffer,
                    engine_analysis=engine_analysis,
                    **params
                )

            idx -= 1

        if r_buffer:
            rule_buffer = r_buffer

        with tempfile.NamedTemporaryFile(mode='r+') as f_tmp:
            f_tmp.write(rule_buffer)
            f_tmp.flush()
            status, diags = testor.analyse_file(
                f_tmp.name,
                engine_analysis=engine_analysis,
                **params
            )

        res = {'status': status, 'info': [], 'warnings': [], 'errors': []}
        for diag in diags:
            content = diag.to_message()
            if content['severity'] == Diagnosis.INFO_LEVEL:
                res['info'].append(content)
            elif content['severity'] == Diagnosis.WARNING_LEVEL:
                res['warnings'].append(content)
            elif content['severity'] == Diagnosis.ERROR_LEVEL:
                res['errors'].append(content)

        # Work around: sls set error as a warning when we have a variable error.
        # but status is kept as False.
        # If suricata config is set when we should have all variables defined
        # then is becomes warning instead of error.
        # we need to change status to True instead of False if there is no other errors.
        res['status'] = status if len(res['errors']) else True

        return res
