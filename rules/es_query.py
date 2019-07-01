from __future__ import unicode_literals


class ESQuery(object):
    def __init__(self, request):
        self.request = request

    def get(self, *args, **kwargs):
        raise NotImplementedError('get method of ESQuery must be overriden')
