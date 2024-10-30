# System & Server Administration

## 1. Introduction to Linux: Philosophy

- **PuTTY**: It allows you to connect to remote computers or devices using various protocols such as secure socket shell (SSH), Telnet, login, and more.

- `ls --all`: Lists all files, including hidden files.
- `~`: Home directory of the current user.
- `apropos`: Command that helps the user when they don't remember the exact command but knows a few keywords related to the command that define its uses or functionality.

- `lsattr [list attribute]`: Command that displays the attributes of a file.
- **SUID & SGID**: Special permissions that allow a user to execute a file with the privileges of the file's owner or group, respectively.
- `which command`: Command that locates tools.
- `file`: Command that identifies the type of a file.

## 2. Partitioning and Storage Management

- **Partition System**: MBR (Master Boot Record) and GPT (GUID Partition Table) are two different partition table formats used to organize data on storage devices.
- **LVM (Logical Volume Management)**: A system for managing disk storage in a more flexible manner than traditional partitioning. LVM provides numerous benefits, such as easy resizing of volumes and the ability to create snapshots.
- **Create Virtual Disk**
- **Network File System (NFS)**: A protocol used to allow file access over a network. While it provides many conveniences, it also has several vulnerabilities that need to be addressed to ensure the security of your systems.

- `lsblk`: Command that lists information about all available or specified block devices.
- `fdisk` and `gdisk`: Commands used to partition storage devices.
- `sudo gdisk /dev/sdb1`: Command to manage GPT partitions.
- `sudo parted /dev/sdb`: Command to manage partitions using the parted utility.
- `sudo mkfs -t`: Command to create a file system on a partition.
- `sudo mount /dev/sdb1 /mnt`: Command to mount a partition.
- `df`: Command that displays the file system disk space usage.

## 3. Network Fundamentals

- **Host-Only Adapter**: A virtual network adapter that creates a private network between the host machine and its virtual machines.
- `nmap --help | grep '-sV'`: Searches the nmap help for the `-sV` option, which is used to probe open ports to determine service/version info.
- `man nmap | grep -I sS`: Searches the nmap manual for the `-sS` option, which is used to perform a TCP SYN scan.
- **Ethical Hacker GPT**: A reference to the Gaara VulnHub machine, which is a vulnerable virtual machine used for ethical hacking practice.
- `ssh -I id_rsa username@ip`: Command to connect to a remote system using SSH with a specific private key.

## 4. Web Server Administration

- `systemctl start apache2`: Command to start the Apache web server.
- `systemctl status apache2`: Command to check the status of the Apache web server.
- `sudo apt-cache search terminator`: Command to search for the Terminator package in the Debian/Ubuntu package repository.
- `sudo dpkg -i .deb-file`: Command to install a Debian package file.

## 5. Privilege Escalation and Kernel Exploitation

- `find / -perm -u=s -user root -exec ls -la {} \;`: Command to find files with the SUID bit set that are owned by the root user.

## 6. Kernel and System Troubleshooting

- `modprobe`: Command used to load and unload kernel modules.
- `/proc/sys/`: Directory that lists configurable parameters for the system.
- `sysctl`: Command that displays or sets kernel parameters at runtime.
- **Kernel Panic**: A mechanism where the system detects and responds to a fatal error, rendering it unstable or unusable.
- `dmesg`: Command that prints messages sent to the kernel message buffer during and after boot.
- `sudo journalctl -u ssh`: Command to view the systemd journal for the SSH service.

## 7. The Linux Boot Process

- **Initrd (Initial RAM Disk)**: A temporary file system loaded into memory to facilitate kernel startup, providing necessary drivers and modules before the root file system is available.
- **GRUB2 (Grand Unified Bootloader)**: The default boot loader for many Linux distributions, responsible for loading the kernel and initrd.

- `grub2-install`: Command to install GRUB2 on a storage device.

## 8. Hardware and Performance Monitoring

- `dmidecode -t cpu`: Command to display CPU information.
- `lspci -tv`: Command to display bus information.
- `lsusb`: Command to list USB devices.
- `/dev`: Directory that contains device files.
- `lscpu`: Command that displays CPU information, including cores, sockets, and caches.
- `cat /proc/cpuinfo`: Command to view the current CPU configuration and per-core details.
- `cat /proc/meminfo`: Command to view memory information.
- `lsmem`: Command to display memory information.

## 9. Process Management

- `pgrep`: Command that searches for processes based on a string and can use `-l` to display the name with PIDs.
- `pidof`: Command that requires the exact process name for finding PIDs.
- `lsof`: Command that lists open files.
- `kill -15 {PID}`: Command to send the SIGTERM signal to a process.
- `kill -9 {PID}`: Command to send the SIGKILL signal to a process, forcefully terminating the process.
- `pkill -15 {name}`: Command to send the SIGTERM signal to processes by name.

## 10. Monitoring and Troubleshooting

- **Process Display Tools**:

  - `top` command
  - CPU time metrics in `top`: %us (user CPU time), %sy (system CPU time), %id (idle CPU time), %wa (I/O wait time), %st (steal time in virtual environments)
  - `htop`: A more user-friendly and interactive version of `top`, with color-coding and customizable display.
  - `ps`: Command that displays detailed process status with various options like `-e`, `-a`, `-u`, `-f`.
  - `lsof`: Command that lists open files and associated processes.

- `systemd-analyze blame`: Command that shows processes that take the most time during boot.
- `sar`: Command that reports system activity, including CPU usage over time, and helps identify high CPU load periods.
- `uptime`: Command that shows how long the system has been running.

## 11. Process States and Swap Management

- **Process States**: Running, Sleeping, Stopped, and Zombie.
- `pstree`: Command that displays a hierarchical view of running processes.
- **Runaway Process**: A process that consumes an excessive amount of system resources, often leading to performance issues.
- **High Utilization**: Indicates that a system is under heavy load, which can be caused by a variety of factors, such as resource-intensive applications, inappropriate configurations, or hardware limitations.
- `nice`: Command that allows you to run programs with a specified priority.
- `fg`: Command that brings a background process to the foreground.
- `jobs`: Command that shows suspended processes.
- `nohup`: Command that prevents a process from stopping when the user logs off.
- `mkswap`: Command that creates and configures swap space.
- `swapon`: Command that activates swap space.
- `swapoff`: Command that deactivates swap space.
- `free`: Command that displays the amount of free and used memory in the system.
- `vmstat`: Command that reports virtual memory statistics.
- **OOM (Out of Memory)**: A condition where the system runs out of available memory, causing the kernel to terminate processes to free up memory.

## 12. Date and Time Management

- `date +%V`: Command that displays the ISO 8601 week number.
- `date +%Y`: Command that displays the current year.
- `set-keymap {keymap}`: Command that configures the keyboard layout.
- `list-keymaps`: Command that lists all available keyboard layouts.
- `set-locale {locale}`: Command that sets the system locale.

## 13. Network Configuration and Troubleshooting

- **TCP/IP**: The fundamental protocol suite used for communication on the internet.
- **UDP**: A connectionless transport layer protocol used in network communication.
- **IPv4**: The fourth version of the Internet Protocol, using 32-bit addresses.
- **Class C Network**: A network with the first three octets of the IP address fixed, and the last octet used for host addresses (e.g., 192.168.1.x).
- `ifconfig`: Command that displays the configuration for all network interfaces.
- `nmcli`: Command-line tool for managing network settings.
- `nmtui`: Text-based user interface for network configuration.
- `nmgui`: Graphical user interface for network settings.
- `systemctl restart NetworkManager`: Command to restart the NetworkManager service.
- `ethtool`: Command-line tool for querying and controlling network driver and hardware settings.
- **DHCP (Dynamic Host Configuration Protocol)**: A network management protocol that automatically assigns IP addresses and other communication parameters to devices connected to a network.

## 14. Network Security and Monitoring

- **Packet Filtering**: A security mechanism that controls network traffic by examining the headers of packets and applying a set of rules to determine whether to allow or block the packet.
- **Firewall**: A network security system that monitors and controls incoming and outgoing network traffic based on a set of security rules.
- **NMAP (Network Mapper)**: A free and open-source utility for network discovery and security auditing.
- **Wireshark**: A network protocol analyzer that allows you to capture and analyze network traffic.
- **Tcpdump**: A command-line network packet analyzer that allows you to capture and analyze network traffic.
- **Netcat (nc)**: A versatile network utility that can be used for a variety of tasks, including port scanning, file transfers, and simple TCP/UDP connections.

## 15. Storage Technologies

- **SATA (Serial Advanced Technology Attachment)**: A computer bus interface that connects host bus adapters to storage devices such as hard disk drives and solid-state drives.
- **SCSI (Small Computer System Interface)**: A set of standards for physically connecting and transferring data between computers and peripheral devices.
- **SAS (Serial Attached SCSI)**: A computer bus technology that moves data to and from computer storage devices using point-to-point serial connections.
- **MBR (Master Boot Record)**: A partition table format used in IBM-compatible computers to define the partitions on a primary storage device, such as a hard disk drive or solid-state drive.
- **GPT (GUID Partition Table)**: A newer partitioning scheme that addresses the limitations of the older MBR format and provides more flexibility in terms of the number of partitions and the size of each partition.
- **RAID (Redundant Array of Independent Disks)**: A technology that combines multiple disk drive components into a logical unit for the purposes of data redundancy, performance improvement, or both.

## 16. Network-Attached Storage (NAS) and Storage Area Network (SAN)

- **NAS (Network-Attached Storage)**: A storage device connected to a network that allows data access to multiple clients, typically using NFS (Network File System) or SMB (Server Message Block) for file sharing.
- **SAN (Storage Area Network)**: A dedicated high-speed network that connects servers to storage devices, often using Fibre Channel, iSCSI, or FCoE (Fibre Channel over Ethernet) for communication.

## 17. SQL Injection and Web Attacks

- `sqlmap -u url-get-req --dbs`: Command to use sqlmap to find databases on a website.
- `sqlmap -u url -D db-name --tables`: Command to use sqlmap to list tables in a specific database.
- `sqlmap -u url -D db-name -T users --columns`: Command to use sqlmap to list columns in a specific table.
- `sqlmap -u url -D db-name -T users -C uname,pass --dump`: Command to use sqlmap to dump data from specific columns in a table.
- **Shell File Upload Attack**: A type of web application attack where an attacker attempts to upload a malicious shell script to the server, allowing them to execute arbitrary commands.
- **Dedicated Server vs. Shared Server**: The main difference between a dedicated server and a shared server is that a dedicated server is a physical server that is exclusively used by a single organization, while a shared server is a physical server that is shared among multiple organizations or users.

## 18. Exploitation and Penetration Testing

- **EternalBlue**: A software vulnerability in the Microsoft Server Message Block 1.0 (SMBv1) protocol that was exploited by the WannaCry ransomware attack.
- **Exploit**: A piece of code, software, or a sequence of commands that takes advantage of a vulnerability or bug in a system, application, or network.
- **Payload**: The code or action that is executed on the target system after a successful exploit.
- `nmap --script=smb-vul* 10.0.2.7`: Command to use nmap to scan for SMB vulnerabilities on the target system.
- **Metasploit**: A popular open-source framework for developing, testing, and using exploit code.
- **msfvenom**: A Metasploit utility used to generate payloads for various platforms and architectures.
- **Reverse TCP**: A type of payload where the victim's system initiates the connection to the attacker's system.
- **Bind TCP**: A type of payload where the attacker's system initiates the connection by listening for incoming connections on a specific port.

## 19. Denial of Service (DoS) and Distributed Denial of Service (DDoS) Attacks

- **Denial of Service (DoS)**: An attack that aims to make a machine or network resource unavailable to its intended users, typically by overwhelming the target with traffic or sending it invalid requests.
- **Botnets**: A collection of internet-connected devices, each of which is running one or more bots (software applications that run automated tasks), that are used to perform distributed denial-of-service (DDoS) attacks.
- **DDoS (Distributed Denial of Service)**: An attack that attempts to disrupt the normal traffic of a targeted server, service, or network by overwhelming the target or its surrounding infrastructure with a flood of internet traffic.
- **WAMP (Windows, Apache, MySQL, PHP)**: A software stack for Windows that includes the Apache web server, MySQL database, and PHP programming language.
- **XAMPP**: A popular open-source software stack that includes the Apache web server, MySQL database, and PHP programming language, among other components.
- **XerXes**: A powerful DoS tool developed by Mr. Thg.
- `hping3 -c 20000 -d 100 -S -w 64 -p 80 --flood --rand-source`: Example command to perform a DoS attack using the hping3 tool.

## 20. System Configuration and Management

- **System Settings**: Configuring various settings related to the Windows operating system, such as system preferences, device settings, display and sound settings, power options, and program and feature management.
- **Remote Code Execution (RCE)**: A type of cyber-attack where an attacker can remotely execute commands on someone else's computing device.
- `.robo.txt`: A file that contains instructions for bots that tell them which webpages they can and cannot access.
- **ACPI (Advanced Configuration and Power Interface)**: An open standard that allows operating systems to configure and discover computer hardware components.
- `msinfo32`: A tool that provides detailed information about the current state of a Windows system.
- **UAC (User Account Control)**: A Windows security feature that prevents unauthorized changes to the operating system.
- **MMC (Microsoft Management Console)**: A component of Microsoft Windows that provides system administrators and advanced users an interface for configuring and monitoring the system.
- `Resource Monitor`: A Windows tool that provides detailed information about system resource utilization.
- `regedit.exe`: The Windows Registry Editor.
- `services.msc`: The Windows Services console.
- `taskschd.msc`: The Windows Task Scheduler.
- `/?`: Displays the help information for a command.
- `xcopy`: A more powerful copying command than the `COPY` command, especially useful for backup purposes.
- `robocopy`: A Windows command-line tool that allows users to copy files, directories, and drives from one location to another.
- `md`: Creates a directory or subdirectory.
- `rd`: Removes a directory.

## 21. Windows Installation and Recovery

- **Unattended Installation**: A scripted process that automatically installs an operating system or software using a configuration file, with minimal user intervention.
- **Boot Manager**: The component responsible for loading the operating system when the computer starts.
- **Image Deployment**: The process of deploying a pre-configured operating system image to multiple devices.
- **Boot Methods**: Legacy BIOS reads the Master Boot Record (MBR), while UEFI
