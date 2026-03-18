import orjson
from rest_framework.parsers import JSONParser
from rest_framework.renderers import JSONRenderer


class ORJSONRenderer(JSONRenderer):
    def render(self, data, accepted_media_type=None, renderer_context=None):
        if data is None:
            return b""

        return orjson.dumps(data, option=orjson.OPT_NAIVE_UTC | orjson.OPT_NON_STR_KEYS)


class ORJSONParser(JSONParser):
    def parse(self, stream, media_type=None, parser_context=None):
        return orjson.loads(stream.read())
