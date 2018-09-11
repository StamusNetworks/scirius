# coding: utf-8
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

This code is based on hogments by Rune Hammersland (https://github.com/yaunj/hogments)
"""

from pygments.lexer import RegexLexer, include, bygroups
from pygments import highlight
from pygments.formatters import HtmlFormatter
import pygments.token as t

class SuriLexer(RegexLexer):
    name = 'suricata'
    aliases = ['suricata']
    filenames = ['*.rules']

    tokens = {
        'root': [
            (r'#.*$', t.Comment),
            (r'(\$\w+)', t.Name.Variable),
            (r'\b(any|(\d{1,3}\.){3}\d{1,3}(/\d+)?)', t.Name.Variable),
            (r'^\s*(log|pass|alert|activate|dynamic|drop|reject|sdrop|'
             r'ruletype|var|portvar|ipvar)',
                t.Keyword.Type),
            (r'\b(metadata)(?:\s*:)', t.Keyword, 'metadata'),
            (r'\b(reference)(?:\s*:)', t.Keyword, 'reference'),
            (r'\b(sid|priority|rev|classtype|threshold|metadata|reference|'
             r'tag|msg|content|uricontent|pcre|ack|seq|depth|distance|'
             r'within|offset|replace|rawbytes|byte_test|'
             r'byte_jump|sameip|geoip|ip_proto|flowbits|window|ftpbounce|isdataat|'
             r'id|rpc|dsize|flowvar|flowint|pktvar|noalert|flow|ipv4-csum|'
             r'tcpv4-csum|tcpv6-csum|udpv4-csum|udpv6-csum|icmpv4-csum|icmpv6-csum|'
             r'stream_size|ttl|itype|icode|tos|icmp_id|icmp_seq|detection_filter|decode-event|'
             r'ipopts|flags|fragbits|fragoffset|gid|nfq_set_mark|tls.version|tls.subject|tls.issuerdn|'
             r'tls.fingerprint|tls.store|'
             r'ssh.protoversion|ssh.softwareversion|ssl_version|'
             r'ssl_state|byte_extract|file_data|pkt_data|app-layer-event|app-layer-protocol|'
             r'dce_iface|dce_opnum|dce_stub_data|asn1|engine-event|stream-event|'
             r'filename|fileext|filestore|filemagic|filemd5|filesize|'
             r'l3_proto|luajit|iprep)|'
             r'(?:\s*:)',
                t.Keyword),
            (r'\b(tcp|udp|icmp|ip)', t.Keyword.Constant),
            (r'\b(hex|dec|oct|string|type|output|any|engine|soid|service|fast_pattern|nocase|'
             r'http_cookie|http_method|urilen|http_client_body|http_server_body|http_header|'
             r'http_raw_header|http_uri|http_raw_uri|http_stat_msg|http_stat_code|http_user_agent|'
             r'http_host|http_raw_host|'
             r'dns_query|'
             r'norm|raw|relative|bytes|big|little|align|invalid-entry|'
             r'enable|disable|client|server|both|either|printable|binary|'
             r'all|session|host|packets|seconds|bytes|src|dst|track|by_src|'
             r'by_dst|uri|header|cookie|utf8|double_encode|non_ascii|'
             r'uencode|bare_byte|ascii|iis_encode|bitstring_overflow|'
             r'double_overflow|oversize_length|absolute_offset|'
             r'relative_offset|rr|eol|nop|ts|sec|esec|lsrr|lsrre|'
             r'ssrr|satid|to_client|to_server|from_client|from_server|'
             r'established|not_established|stateless|no_stream|only_stream|'
             r'no_frag|only_frag|set|setx|unset|toggle|isset|isnotset|'
             r'noalert|limit|treshold|count|str_offset|str_depth|tagged)',
                t.Name.Attribute),
            (r'(<-|->|<>)', t.Operator),
            (ur'”', t.String, 'fancy-string'),
            (ur'“', t.String, 'fancy-string'),
            (r'"', t.String, 'dq-string'),
            (r'\'', t.String, 'sq-string'),
            (r'(\d+)', t.Number),
            (r';', t.Punctuation),
            (r'\\', t.String.Escape),
            (r'\s+', t.Whitespace),
        ],
        'hex': [
            (r'\|([a-fA-F0-9 ]+)\|', t.Number.Hex),
        ],
        'dq-string': [
            include('hex'),
            (r'([^"])', t.String),
            (r'"', t.String, '#pop')
        ],
        'sq-string': [
            include('hex'),
            (r'([^\'])', t.String),
            (r'\'', t.String, '#pop')
        ],
        'fancy-string': [
            include('hex'),
            (ur'([^”])', t.String),
            (ur'”', t.String, '#pop')
        ],
        'metadata': [
            (r'\s', t.Whitespace),
            (r'([\w_-]+)(\s+)([\w_-]+)',
                bygroups(t.Name.Variable, t.Whitespace, t.Name.Attribute)),
            (r';', t.Punctuation, '#pop'),
        ],
        'reference': [
            (r'(\w+)(,)(?:\s*)([^;]+)',
                bygroups(t.Name.Variable, t.Punctuation, t.Name.Attribute)),
            (r';', t.Punctuation, '#pop')
        ]
    }

def SuriHTMLFormat(rule):
    return highlight(rule, SuriLexer(), HtmlFormatter())
