from __future__ import unicode_literals, print_function

from django.conf import settings
import importlib

_backend = None

ES_BACKENDS = {
    'ELASTICSEARCH':   ('rules.es_client', 'ESClient'),
    'HUMIO':           ('rules.humio_client', 'HumioClient')
}


def get_es_backend():
    """
    Get the correct es backend
    :return: humio or elastic implementation of ESBackend
    """
    global _backend
    if not _backend:
        pair = ES_BACKENDS[settings.ES_BACKEND]
        backend_import = importlib.import_module(pair[0])
        backend_class = getattr(backend_import, pair[1])
        _backend = backend_class()

    return _backend
