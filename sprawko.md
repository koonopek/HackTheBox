<center>
## 1. [Projekt] Zadanie 1
**Przedmiot:** Podstawy Bezpieczeństwa Oprogramowania
**Prowadzący:** dr inż. Ostap Hubert
**Autor:** Konopka Michał WCY18IJ4S1
</center>

<div style="page-break-after: always"></div>

## 2. Zadania

### 2.1 Zadanie 1
**Nazwa:** Emdee five for life
**Punkty:** 20
**Flaga** HTB{N1c3_ScrIpt1nG_B0i!}
1. Na wejściu otrzymujemy losowy łańcuch znaków
2. Mamy zadanie go zahashować, funkcją hashującą MD5, gdy robimy to z wykorzystaniem narzędzia online, to w odpowiedzi znajdujemy wskazówkę: `Too slow`
3. W dev-tools zakładka network, aby prześledzić requesty:
     * Do generowania losowego string'a `GET http://188.166.168.204:31661/`
     * Do wysyłania zahashowanego string'a `POST http://188.166.168.204:31661/`
4. Napisałem skrypt (nodejs), który miał byc za zadanie szybszy ode mnie :
```javascript
const Axios = require('axios').default;
const cheerio = require('cheerio');
const md5 = require('md5');
const fetch = require('node-fetch');

(async () => {
    const axios = Axios.create(); 
    const url = 'http://188.166.168.204:31661/';
    const responseGet = (await axios.get(url));
    const html = responseGet.data;
    const cookie = responseGet.headers['set-cookie'][0];
    const $ = cheerio.load(html);
    const value = $('h3')[0].children[0].data;

    fetch("http://188.166.168.204:31661/", {
        "headers": {
          "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
          "accept-language": "pl-PL,pl;q=0.9,en-US;q=0.8,en;q=0.7",
          "cache-control": "max-age=0",
          "content-type": "application/x-www-form-urlencoded",
          "sec-gpc": "1",
          "upgrade-insecure-requests": "1",
          "cookie": cookie.split(';')[0]
        },
        "referrer": "http://188.166.168.204:31661/",
        "referrerPolicy": "strict-origin-when-cross-origin",
        "body": `hash=${md5(value)}`,
        "method": "POST",
        "mode": "cors"
      }).then(r => r.text()).then(console.log);
})();
```
*Skrypt najpierw odpytuję stronę, w odpowiedzi dostaję html z którego odczytuję znaki do zahashowania, w odpowiedzi otrzymuję również ciasteczko sesji które następnie przekazywane jest przy następnym zapytaniu. Ostatnie zapytanie POST, zostało wygenerowane z DevTools, opcją copy as: Node-Fetch*
5. Rezultat ![image](flag1.png)

<div style="page-break-after: always"></div>

### 2.2 Zadanie 2
**Nazwa:** Emdee five for life
**Punkty:** 20
**Flaga** HTB{N1c3_ScrIpt1nG_B0i!}