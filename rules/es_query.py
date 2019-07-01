from __future__ import unicode_literals

import json
import logging
import socket

import urllib2


# ES requests timeout (keep this below Scirius's ajax requests timeout)
TIMEOUT = 30

es_logger = logging.getLogger('elasticsearch')


class ESQuery(object):
    def __init__(self, request):
        self.request = request

    def _urlopen(self, url, data=None, contenttype='application/json'):
        from rules.es_graphs import ESError
        headers = {'content-type': contenttype}
        req = urllib2.Request(url, data, headers)

        try:
            out = urllib2.urlopen(req, timeout=TIMEOUT)
        except (urllib2.URLError, urllib2.HTTPError, socket.timeout) as e:
            msg = url + '\n'
            if isinstance(e, socket.timeout):
                msg += 'Request timeout'
            elif isinstance(e, urllib2.HTTPError):
                msg += '%s %s\n%s\n\n%s' % (e.code, e.reason, e, data)
            else:
                msg += repr(e)
            es_logger.exception(msg)
            raise ESError(msg)

        out = out.read()
        out = json.loads(out)
        return out

    def get(self, *args, **kwargs):
        raise NotImplementedError('get method of ESQuery must be overriden')
