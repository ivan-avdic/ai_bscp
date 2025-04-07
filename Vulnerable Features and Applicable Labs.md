# Vulnerable Features and Applicable Labs

## Check Image
- Vulnerability: Path Traversal  
  - Labs:
    - File path traversal, simple case  
    - File path traversal, traversal sequences blocked with absolute path bypass  
    - File path traversal, traversal sequences stripped with superfluous URL-decode  
    - File path traversal, validation of file extension with null byte bypass  
    - File path traversal, validation of start of path

## Check Stock
- Vulnerability: OS Command Injection  
  - Labs:
    - OS Command Injection, Simple Case

## Submit Feedback
- Vulnerability: Blind OS Command Injection – Output Redirection  
  - Labs:
    - Blind OS Command Injection with Output Redirection

- Vulnerability: Blind OS Command Injection – Time Delays  
  - Labs:
    - Blind OS Command Injection with Time Delays

- Vulnerability: Blind OS Command Injection – Out-of-Band Interaction  
  - Labs:
    - Blind OS Command Injection with Out-of-Band Interaction

## Login Form
- Vulnerability: Username Enumeration – Different Responses  
  - Labs:
    - Username enumeration via different responses  
    - Username enumeration via subtly different responses

- Vulnerability: Username Enumeration – Account Lock  
  - Labs:
    - Username enumeration via account lock

- Vulnerability: Username Enumeration – Response Timing  
  - Labs:
    - Username enumeration via response timing

- Vulnerability: Brute-force Protection Bypass – IP Alternation  
  - Labs:
    - Broken brute-force protection, IP block

- Vulnerability: 2FA Bypass – Brute-force of MFA Code  
  - Labs:
    - 2FA bypass using a brute-force attack

- Vulnerability: Brute-force Protection Bypass – Multi-Password Submission  
  - Labs:
    - Broken brute-force protection, multiple credentials per request

- Vulnerability: SQL Injection – Login Bypass  
  - Labs:
    - SQL injection vulnerability allowing login bypass

- Vulnerability: SQL Injection – WHERE Clause Bypass  
  - Labs:
    - SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

- Vulnerability: SQL Injection – UNION SELECT  
  - Labs:
    - SQL injection UNION attack, determining the number of columns returned by the query  
    - SQL injection UNION attack, finding a column containing text  
    - SQL injection UNION attack, retrieving data from other tables  
    - SQL injection UNION attack, retrieving multiple values in a single column

- Vulnerability: Blind SQL Injection – Conditional Responses  
  - Labs:
    - Blind SQL injection with conditional responses

- Vulnerability: Blind SQL Injection – Error-Based  
  - Labs:
    - Blind SQL injection with conditional errors  
    - Visible error-based SQL injection

- Vulnerability: Blind SQL Injection – Time Delays  
  - Labs:
    - Blind SQL injection with time delays  
    - Blind SQL injection with time delays and information retrieval

## XML-Encoded Input
- Vulnerability: SQL Injection – Filter Bypass via Encoding  
  - Labs:
    - SQL injection with filter bypass via XML encoding

## Tracking Cookie / Header Field
- Vulnerability: SQL Injection – Out-of-Band Interaction  
  - Labs:
    - Blind SQL injection with out-of-band interaction  
    - Blind SQL injection with out-of-band data exfiltration

## Database-Specific Enumeration
- Vulnerability: SQL Injection – DB Discovery  
  - Labs:
    - SQL injection attack, querying the database type and version on MySQL and Microsoft  
    - SQL injection attack, querying the database type and version on Oracle

## Database Contents
- Vulnerability: SQL Injection – Schema Enumeration  
  - Labs:
    - SQL injection attack, listing the database contents on non-Oracle databases  
    - SQL injection attack, listing the database contents on Oracle

## Stay Logged In Cookie
- Vulnerability: Offline Token Cracking – MD5  
  - Labs:
    - Brute-forcing a stay-logged-in cookie  
    - Offline password cracking

## Change Password
- Vulnerability: Password Brute-Force via Error Response  
  - Labs:
    - Password brute-force via password change

## Forgot Password
- Vulnerability: Password Reset Link Poisoning  
  - Labs:
    - Password reset poisoning via middleware