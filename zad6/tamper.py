#!/usr/bin/env python
from lib.core.enums import PRIORITY
__priority__ = PRIORITY.NORMAL
def dependencies():
    pass
def tamper(payload, **kwargs):
    def toUtf8(payload: str): return ''.join(map(lambda s: str(hex(ord(s))), payload)).replace('0x','\\u00')
    
    return toUtf8(payload)