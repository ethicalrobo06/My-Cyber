Here's a comprehensive explanation of each topic from your notes, converted into a structured `README.md` format. I’ve also included relevant sections regarding Windows for completeness.

````markdown
# Linux and Windows System Administration Guide

## User Types

- **Root User**: This user has the highest level of privileges and can perform any action on the system, including modifying system files and user accounts.
- **Non-Root User**: This user has limited privileges and cannot perform administrative tasks without elevated permissions.

### Prompt Symbols

- **#**: Indicates the root user.
- **$**: Indicates a non-root user.

## Terminal Multiplexer (tmux)

- **Ctrl + b -> Shift + %**: Split the terminal vertically.
- **Ctrl + b -> Shift + "**: Split the terminal horizontally.
- **Ctrl + b -> Up Arrow Key**: Switch to the pane above.

## File Navigation and Commands

- **pwd**: Print Working Directory; shows the current directory.
- **cd**: Change Directory; navigates to the target directory.

### Command Structure

```bash
$ command [options] [arguments]
```
````

- **Command**: Name of the application.
- **Options**: Control the behavior of commands/applications.
- **Arguments**: Change the behavior of commands/applications.

### Listing Files

- **ls**: Lists files in the current directory.
  - **-a**: Shows all files, including hidden ones.
  - **-l**: Long listing format.
  - **-h**: Human-readable sizes.
  - **-t**: Sort by modification time.
  - **-r**: Reverse the order of the sort.

### File Types and Navigation

- **.**: Represents the current directory.
- **..**: Represents the parent directory.
- **Hidden Files**: Files beginning with a dot (e.g., `.file`).

## Virtualization

- **Virtualization**: Logical sharing of physical resources.
  - **Type 1 Hypervisor (Bare Metal)**: More expensive but provides better performance.
  - **Type 2 Hypervisor**: Runs on a host operating system.

## Operating System Concepts

- **OS**: The interface between the user and hardware.
- **Kernel**: Manages hardware operations and system resources.
- **CLI vs. GUI**: Command Line Interface (CLI) interacts directly with the kernel, while Graphical User Interface (GUI) provides a user-friendly way to interact with the OS.

## Security Concepts

- **RFI**: Radio Frequency Identification.
- **PII**: Personally Identifiable Information.
- **Authentication**:

  - **SFA (Single Factor Authentication)**: One method of authentication.
  - **MFA (Multi-Factor Authentication)**: Multiple methods (something you know, have, are, etc.).

  Example:

  - **Fingerprint Scan** (something you are)
  - **Password & PIN** (something you know)
  - **ID card & OTP** (something you have)

- **Authorization**: Determines the level of access for a user.
- **Non-repudiation**: Ensures that neither the sender nor the receiver can deny sending or receiving a message, often enforced via digital signatures.

## Core Security Principles

- **CIA Triad**: Confidentiality, Integrity, Availability.
- **Non-repudiation**: Ensures accountability in communications.
- **Homography**: Refers to items that appear the same.
- **Homograph Attack**: A type of attack leveraging visually similar characters in different scripts (e.g., IDNs).

## Types of Hackers

- **White Hat**: Ethical hackers working for organizations.
- **Gray Hat**: Operate between ethical and unethical hacking.
- **Black Hat**: Malicious hackers with harmful intent.
- **Script Kiddies**: Use existing tools to perform hacks without understanding.
- **Hacktivists**: Hack for social or political reasons.
- **APT**: Advanced Persistent Threat; organized groups with malicious intent.
- **State-sponsored Hackers**: Operate on behalf of a government.

## File System Basics

- **Directory Structure**:
  - **/**: Root directory.
  - **~**: Home directory for the current user.

### Common Directories

- **/home**: Contains user home directories.
- **/bin**: Binary executables.
- **/var**: Variable files, including logs.
- **/boot**: Contains kernel and boot configuration files.
- **/dev**: Device files.
- **/proc**: Information about running processes.
- **/etc**: Configuration files for software.
- **/tmp**: Temporary files accessible by all users.
- **/skel**: Skeleton directory for user creation.

### Path Types

- **Relative Path**: Relative to the current directory.
  - Example: `cd config` (from `/etc` to `/etc/config`).
- **Absolute Path**: Complete path from the root directory.
  - Example: `cd /etc/config`.

### File Manipulation Commands

- **mkdir**: Create directories.
- **touch**: Create files.
- **rm**: Remove files.
- **rmdir**: Remove empty directories.
- **rm -rf**: Forcefully remove non-empty directories.

### Viewing User Information

- **whoami**: Displays the current user.
- **who**: Shows currently logged-in users.
- **w**: Displays detailed information about logged-in users.
- **last**: Displays successful login history.
- **lastb**: Displays failed login attempts.

## User Management

- **adduser username**: Adds a new user.
- **userdel -r username**: Deletes a user and their home directory.
- **passwd**: Changes a user's password.
- **cat /etc/passwd**: Lists all users.
- **cat /etc/shadow**: Lists hashed passwords.
- **cat /etc/group**: Lists all groups.

## System Management

- **hostname**: Shows the system's hostname.
- **hostnamectl**: Displays detailed hostname information.
- **timedatectl**: Manages time and date settings.

### Time Zone Management

- **timedatectl set-timezone Asia/Kolkata**: Sets the timezone.
- **timedatectl set-ntp true**: Enables NTP for automatic time updates.

## File Compression

- **tar**: Tool for archiving files.

  - **tar -cvf archive.tar file1 file2**: Create an archive.
  - **tar -tf archive.tar**: List archive contents.
  - **tar -xvf archive.tar**: Extract contents.

- **gzip**: Compression tool.
  - **gzip file**: Compress a file.
  - **gzip -d file.gz**: Decompress a file.

## Log Analysis

- **wc**: Word count utility.
  - **wc -l**: Count lines in a file.
  - **wc -w**: Count words in a file.
  - **wc -m**: Count characters in a file.

## Shell Shortcuts

- **Ctrl + a**: Move to the beginning of the command line.
- **Ctrl + e**: Move to the end of the command line.
- **Ctrl + k**: Cut text from the current position to the end.
- **Ctrl + y**: Paste the cut text.

## System Information

- **uname**: Displays system information.
  - **uname -a**: Displays all system information.
  - **uname -r**: Displays the kernel version.

## Windows Concepts (Additional Information)

### User Management

- **Administrator Account**: Similar to root in Linux; has full system control.
- **Standard User Account**: Similar to non-root; limited privileges.

### Command Prompt Basics

- **dir**: Lists files and directories in the current directory.
- **cd**: Change directory, similar to Linux.
- **del**: Deletes files.
- **mkdir**: Creates directories.

### System Management

- **tasklist**: Lists running processes.
- **taskkill /IM process_name**: Kills a specified process.
- **systeminfo**: Displays detailed system information.

Sure! Here's an explanation of the various topics you mentioned, including details about asset value and calculations related to loss expectancy, Linux commands, user and file management, Windows commands, and cryptography concepts.

### Asset Value and Loss Expectancy

1. **Asset Value (AV)**: This refers to the monetary value of a piece of hardware or asset that is crucial for operations. It is an important component in risk management and financial assessments.

2. **Single Loss Expectancy (SLE)**: This is calculated using the formula:
   \[
   \text{SLE} = \text{AV} \times \text{EF}
   \]
   where **EF (Exposure Factor)** is the percentage of the asset's value that would be lost due to a single incident.

3. **Annual Loss Expectancy (ALE)**: This metric helps organizations estimate the expected loss over a year, calculated as:
   \[
   \text{ALE} = \text{SLE} \times \text{ARO}
   \]
   where **ARO (Annual Rate of Occurrence)** is the expected number of incidents per year.

4. **Public Resource Exposure**: Public resources often have a higher EF compared to internal resources because they are more accessible and therefore more vulnerable to attacks.

5. **Live Risk**: This refers to potential risks that are currently affecting operations, influenced by government policies and other external factors.

---

### Linux Commands and File Management

1. **Viewing File Content**:

   - `head -2 /etc/passwd`: Displays the first two lines of the `/etc/passwd` file.
   - `tail -9 /etc/passwd`: Shows the last nine lines of the `/etc/passwd` file.
   - `nano test.txt` or `vi test.txt`: Opens the `test.txt` file in a text editor (nano or vi).

2. **Searching for Files**:

   - `locate filename`: Finds files by name but doesn't track recent changes.
   - `updatedb`: Updates the database for the `locate` command.
   - `find / -name file-name -size 100c -user tom -name a* 2> /dev/null`: Searches for files named starting with 'a', owned by 'tom', and of size 100 bytes, suppressing error messages.

3. **File and Directory Management**:

   - `ls -l`: Lists files with permissions.
   - `chown new-owner file-name`: Changes the file's owner.
   - `chgrp new-group file-name`: Changes the file's group.

4. **Redirection**:

   - `echo "hii" > a.txt`: Writes "hii" to `a.txt`, overwriting any existing content.
   - `echo "hii" >> a.txt`: Appends "hii" to `a.txt`.
   - `2> /dev/null`: Redirects error messages to the null device.

5. **Shell and History**:
   - `zsh`: A type of shell, similar to Bash.
   - History files are often hidden (like `.bashrc`).

---

### User Management

1. **User Creation and Management**:

   - Users are created with basic config files from `/etc/skel`.
   - User information is recorded in `/etc/passwd`, `/etc/shadow`, and `/etc/group`.

2. **User Commands**:

   - `usermod`: Modifies user accounts.
     - `usermod -c "Politician" username`: Adds a comment.
     - `usermod -l new-username username`: Changes the username.
   - `useradd -c "comment" -d "/tmp/dir" newuser`: Adds a new user with specific attributes.
   - `userdel username`: Deletes a user.
   - `passwd`: Used for password management.

3. **Group Management**:
   - `groupadd groupname`: Creates a new group.
   - `usermod -a -G groupname username`: Adds a user to a group.

### User Management Commands

1. **Adding a New User:**

   - `useradd -c "comment" -d "/tmp/dir" newuser`

2. **Modifying an Existing User:**

   - To add a comment:  
     `usermod -c "Politician" {username}`
   - To change login name:  
     `usermod -l {newusername} {username}`
   - Temporary changing access of an account:  
     `usermod -L {username}` (lock)  
     `usermod -U {username}` (unlock)
   - To set a password:  
     `usermod -p {password} {username}`

3. **Deleting a User:**
   - `userdel {username}` (only deletes user)
   - `userdel -r {username}` (delete user and home directory)

### Password Management

- List all password-related info:  
  `chage -l {username}`
- Manage password settings:
  - Max days: `chage -M {value} {username}`
  - Min days: `chage -m {value} {username}`
  - Warning days: `chage -W {value} {username}`
  - Account expiration: `chage -E {value} {username}`
- **Using `passwd`:**
  - Delete password:  
    `passwd -d {username}`
  - Lock password:  
    `passwd -l {username}`
  - Unlock password:  
    `passwd -u {username}`
  - Force password expiration:  
    `passwd -e {username}`

### Group Management

- **Viewing Groups:**
  - `/etc/group` (list of all groups)
- **Adding/Deleting Groups:**
  - `groupadd {groupname}`
  - `groupdel {groupname}`
- **Managing User Groups:**
  - Add user to a group:  
    `usermod -a -G {groupname} {username}`
  - Remove user from a group:  
    `usermod -r -G {groupname} {username}`

### Permission Management

- **Understanding Permissions:**

  - Format: `-uuu-ggg-ooo-` (owner-group-others)
  - Read (r) = 4, Write (w) = 2, Execute (x) = 1

- **Granting/Revoke Permissions:**
  - Grant: `+`, Revoke: `-`
  - Example: `chmod u+rwx, g+rw, o+r {filename}`
- **Numeric Permissions:**

  - Example: `chmod 644 {filename}`

- **Effective Permissions:**
  - Default umask values:
    - Root: 022
    - Non-root: 002

### Special Permissions

1. **SetUID (s):**  
   Allows users to run an executable with the privileges of the executable's owner.  
   Command:  
   `chmod u+s {filename}`

2. **SetGID (g):**  
   Allows users in a group to run executables with the group privileges or to create files in a directory with the same group ownership.  
   Command:  
   `chmod g+s {directory}`

3. **Sticky Bit:**  
   Only the file owner can delete or modify the file. Commonly set on directories like `/tmp`.  
   Command:  
   `chmod +t {directory}`

### Ownership Management

- Change file ownership:  
  `chown {newowner} {filename}`
- Change both user and group ownership:  
  `chown {username}:{groupname} {filename}`

### File Metadata

- **File Metadata Management:**
  - `stat {filename}`: Displays detailed file status, including time-related attributes.
- **Inode Number:**  
  Each file has an inode number associated with it, which contains metadata.

### Windows Commands

1. **User and Group Management**:

   - `net user`: Displays user accounts.
   - `net user username /add`: Adds a new user.
   - `net user username /del`: Deletes a user.
   - `net localgroup`: Shows all groups.

2. **Network Configuration**:

   - `ipconfig`: Displays network configuration details.
   - `ipconfig /all`: Shows all IP configurations.
   - `getmac`: Displays the MAC address.

3. **Task Management**:

   - `tasklist`: Displays running processes.
   - `tasklist | findstr processname`: Filters the process list.

4. **Firewall Management**:
   - `netsh advfirewall set allprofiles state on`: Turns on the firewall.
   - `netsh advfirewall show currentprofile`: Displays the current firewall profile settings.

---

### Cryptography

1. **Cryptography**: The art of hiding information, ensuring secure communication.

   - **Key Generation**: The first step in encryption.
   - **Symmetric Encryption**: Uses one key for both encryption and decryption.
   - **Asymmetric Encryption**: Uses a pair of keys: a public key for encryption and a private key for decryption.

2. **Encryption Process**:

   - **Caesar Cipher**: A simple substitution cipher where each letter is shifted by a fixed number.
   - **Substitution Ciphers**: Replace characters in the plaintext with other characters.

3. **Block Ciphers**:

   - **Symmetric Algorithms**: Examples include DES (Data Encryption Standard), 3DES (Triple DES), and AES (Advanced Encryption Standard).

4. **Asymmetric Algorithms**:

   - **RSA (Rivest-Shamir-Adleman)**: A widely used asymmetric encryption algorithm.

5. **Hybrid Encryption**: Combines the strengths of both symmetric and asymmetric encryption for security and performance.

---
