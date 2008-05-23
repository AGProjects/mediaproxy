# Copyright (C) 2008 AG Projects
# Author: Ruud Klaver <ruud@ag-projects.com>
#

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
            return ",".join(":".join(str(j) for j in i) for i in value)
        except:
            raise EncodingError("Ill-formatted media information")

    @staticmethod
    def decode_media(value):
        try:
            retval = [i.split(":") for i in value.split(",")]
            for i in retval:
                i[2] = int(i[2])
        except:
            raise DecodingError("Ill-formatted media header")
        return retval


class CodingDict(dict):

    def __init__(self, *args, **kwargs):
        if not args and not kwargs:
            it = []
        elif kwargs:
            it = kwargs.iteritems()
        elif isinstance(args[0], dict):
            it = args[0].iteritems()
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
