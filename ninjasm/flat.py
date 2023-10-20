"""
Module flat: permettant de gèrer un flux de data binaire et d'encoder/packer
"""

import struct
import logging

log = logging.getLogger(__name__)

class Flat:
    def __init__(self):
        self.__bytes = bytearray()

    def _to_int(self, data):
        d = None
        if type(data) is int:
            d = data
        elif type(data) is str:
            if data[-1] in ('b', 'B'):
                log.info(f"DATA 0b binary syntax")
                d = int(data[:-1], 2)
            if data[-1] in ('h', 'H'):
                log.info(f"DATA DB 00h hexa syntax")
                d = int(data[:-1], 16)
            elif len(data) > 2:
                log.info(f"DATA DB 0? syntax")
                match data[:2]:
                    case '0x'|'0X':
                        d = int(data[2:], 16)
                    case '0o'|'0O':
                        d = int(data[2:], 8)
                    case '0b'|'0B':
                        d = int(data[2:], 2)
                    case _:
                        d = int(data)
            if d is None:
                d = int(data)
        return d

    def db(self, data):
        d = self._to_int(data)
        if -128 <= d <= 127:
            self.__bytes += struct.pack('b', d)
        elif d <= 255:
            self.__bytes += struct.pack('B', d)
        else:
            raise RuntimeError(f"Data exceed {__name__}: {type(d)} = {d}")

    @property
    def bytes(self):
        return bytes(self.__bytes)
