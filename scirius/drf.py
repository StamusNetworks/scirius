import orjson
import structlog

from rest_framework.parsers import JSONParser
from rest_framework.renderers import JSONRenderer
from rest_framework.utils.serializer_helpers import ReturnDict, ReturnList


logger = structlog.get_logger("django_structlog")


class ORJSONRenderer(JSONRenderer):
    def render(self, data, accepted_media_type=None, renderer_context=None):
        if data is None:
            return b""

        # Handle DRF wrapped objects
        if isinstance(data, ReturnDict):
            data = dict(data)
        elif isinstance(data, ReturnList):
            data = list(data)

        try:
            return orjson.dumps(data, option=orjson.OPT_NAIVE_UTC | orjson.OPT_NON_STR_KEYS)
        except TypeError:
            # fallback using the default behavior
            logger.debug("Not JSON serializable", type=type(data))
            return super().render(data, accepted_media_type, renderer_context)


class ORJSONParser(JSONParser):
    def parse(self, stream, media_type=None, parser_context=None):
        return orjson.loads(stream.read())
