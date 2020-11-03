
"""Header encoding and decoding rules for communication between the dispatcher and relay components"""

class EncodingError(Exception):
    pass


class DecodingError(Exception):
    pass


class MediaProxyHeaders(object):

    @classmethod
    def encode(cls, name, value):
        func_name = "encode_%s" % name
        if hasattr(cls, func_name):
            return getattr(cls, func_name)(value)
        else:
            return value

    @classmethod
    def decode(cls, name, value):
        func_name = "decode_%s" % name
        if hasattr(cls, func_name):
            return getattr(cls, func_name)(value)
        else:
            return value

    @staticmethod
    def encode_cseq(value):
        return str(value)

    @staticmethod
    def decode_cseq(value):
        try:
            return int(value)
        except ValueError:
            raise DecodingError("Not an integer: %s" % value)

    @staticmethod
    def encode_type(value):
        if value not in ["request", "reply"]:
            raise EncodingError('"type" header should be either "request" or "reply"')
        return value

    @staticmethod
    def decode_type(value):
        if value not in ["request", "reply"]:
            raise DecodingError('"type" header should be either "request" or "reply"')
        return value

    @staticmethod
    def encode_media(value):
        try:
            return ','.join(':'.join([type, ip, str(port), direction] + ['%s=%s' % (k, v) for k, v in parameters.items()]) for type, ip, port, direction, parameters in value)
        except:
            raise EncodingError("Ill-formatted media information")

    @staticmethod
    def decode_media(value):
        try:
            streams = []
            for stream_data in (data for data in value.split(",") if data):
                stream_data = stream_data.split(":")
                type, ip, port, direction = stream_data[:4]
                parameters = dict(param.split("=") for param in stream_data[4:] if param)
                streams.append((type, ip, int(port), direction, parameters))
            return streams
        except:
            raise DecodingError("Ill-formatted media header")


class CodingDict(dict):

    def __init__(self, *args, **kwargs):
        if not args and not kwargs:
            it = []
        elif kwargs:
            it = iter(kwargs.items())
        elif isinstance(args[0], dict):
            it = iter(args[0].items())
        else:
            try:
                it = iter(args[0])
            except:
                dict.__init__(self, *args, **kwargs)
                return
        dict.__init__(self)
        for key, value in it:
            self.__setitem__(key, value)


class EncodingDict(CodingDict):

    def __setitem__(self, key, value):
        encoded_value = MediaProxyHeaders.encode(key, value)
        dict.__setitem__(self, key, encoded_value)


class DecodingDict(CodingDict):

    def __setitem__(self, key, value):
        decoded_value = MediaProxyHeaders.decode(key, value)
        dict.__setitem__(self, key, decoded_value)
