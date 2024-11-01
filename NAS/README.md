# Network Administration

### Communication Components

1. Sender
2. Receiver
3. Transmission Medium
4. Protocols

## Network

A network is a collection of devices with the capability to send and receive information or data via any kind of transmission medium.

## Port Numbers

There are 65,535 possible port numbers.

## Network Models

### OSI (Open System Interconnect) Model

- **Application Support Layer**
- **Network Support Layer**
  - **Physical Layer**: Bit conversion, Sync, Topology, Transmission Medium (Devices: Hub, Repeater, Modem)
  - **Data Link Layer**: MAC address, Communication in local network (Devices: Switch, Bridge, Wireless Switch)
  - **Network Layer**: IP/Logical Address, Routing, Path Determination (Devices: Router, L3 Switch)
  - **Transport Layer**: Port Addresses, Segmentation, Reassembling, Flow Control, Error Control
  - **Session Layer**: Dialog Control, Session Management, Authorization, Authentication
  - **Presentation Layer**: Data Encoding, Encryption, Compression
  - **Application Layer**: User Interface

## Transmission Models

1. **Simplex**: One-way communication (e.g., keyboard)
2. **Half Duplex**: One-way communication at a time (e.g., walkie-talkie)
3. **Full Duplex**: Two-way communication (e.g., cell phone)

## Signals

1. Electric
2. Optic
3. Radio

## Network Devices

- **Switch**: Connects devices on the same network, has 65,535 ports
- **Port Number**: Used for process-to-process communication in the Transport Layer
- **ARP (Address Resolution Protocol)**: Finds MAC address using IP address, maintains an ARP table
- **Hub**: Broadcasts to all connected devices, causes collisions
- **Switch**: Self-learning device, broadcasts only on the first occurrence

## Encapsulation and Decapsulation

- **Encapsulation**: Occurs at the sender side
- **Decapsulation**: Occurs at the receiver side

## TCP/IP

- **IP Protocol**: Provides logical addressing (IPv4 and IPv6)
- **ARP (Address Resolution Protocol)**: Finds MAC address using IP address
- **RARP (Reverse Address Resolution Protocol)**: Maps MAC address to IP address
- **ICMP (Internet Control Message Protocol)**: Used for error messages and troubleshooting
- **IGMP (Internet Group Message Protocol)**
- **Routing Protocols**: RIP, OSPF, BGP, EIGRP
- **UDP (User Datagram Protocol)**: Unreliable, connectionless
- **TCP (Transmission Control Protocol)**: Reliable, connection-oriented

## Application Layer Protocols

- **FTP (File Transfer Protocol)**: [20, 21]
- **SSH (Secure Shell)**: [22]
- **Telnet**: [23]
- **SMTP (Simple Mail Transfer Protocol)**: [25]
- **HTTP (Hypertext Transfer Protocol)**: [80]
- **HTTPS (Hypertext Transfer Protocol Secure)**: [443]
- **DNS (Domain Name System)**: [53]
- **IMAP (Internet Message Access Protocol)**: [143]
- **POP (Post Office Protocol)**: [110]
- **DHCP (Dynamic Host Configuration Protocol)**: Server Port [67], Client Port [68]

---

# MAC Address Types and IP Addressing

## MAC Address Types

- **Least Significant Bit (LSB)**: If LSB is 0, then it is unicast.
  - Example: A4 (binary: 10100100)
  - Types:
    1. **Unicast**
    2. **Multicast**
    3. **Broadcast**: FF:FF:FF:FF:FF:FF

## Bits Representation

A single bit can represent 2 possible values: 0 (zero) and 1 (one). In the case of IPv4, n bits can represent \(2^n\) distinct values.

- **IPv4**: (32 bits) -> \(2^{32}\)

## IP Address Classes

- **Class A**: 0 - 126 (2^8)
- **Class B**: 128 - 191
- **Class C**: 192 - 223
- **Class D**: 224 - 239 (2^7)
- **Class E**: 240 - 255 (2^6)

| Class | Range     | NID Bits | Host Bits | No. of Networks | No. of Hosts | Subnet Mask   |
| ----- | --------- | -------- | --------- | --------------- | ------------ | ------------- |
| A     | 0 - 127   | 8        | 24        | \(2^7\)         | \(2^{24}-2\) | 255.0.0.0     |
| B     | 128 - 191 | 16       | 16        | \(2^{14}\)      | \(2^{16}-2\) | 255.255.0.0   |
| C     | 192 - 223 | 24       | 8         | \(2^{21}\)      | \(2^{8}-2\)  | 255.255.255.0 |

### Example Ranges

- Class A: 111.21.56.78 --------- 111.255.255.255
- Class B: 136.23.45.6 ------------- 136.23.255.255
- Class C: 192.168.42.23 ----------- 192.168.42.255

**Maximum Networks**: \(2^{21}\) in class and minimum hosts \(2^{8}\).

## Network Addressing

- **Network Address**: First address (invalid in every network)
- **Broadcast Address**: Last address (invalid in every network)

### Wildcard Mask (WCM)

WCM is calculated as follows:

**Step 1**: Network Address = IP & SM (binary last part)
Example:

- IP: 192.168.10.50
- Subnet Mask: 255.255.255.0
- Result: 192.168.10.0

**Step 2**: Wildcard Mask = MAX SM - Given SM

- MAX SM: 255.255.255.255
- Given SM: 255.255.255.0
- Result: 0.0.0.255
- **Broadcast Address**: Network Address + WCM

### Additional Example

For IP: 175.250.10.90 & Subnet Mask: 255.255.0.0

- WCM: 0.0.255.255

### Detailed Example

- IP: 175.168.10.59 / Subnet Mask: 255.255.255.248
  Binary representation:

00111011 (175)
11111000 (168)

---

00111000 -> 56
11001000 (10)
11100000

---

11000000

**Most Significant Bit**: 1 - 198

- 1111: 240
- 11111: 248
- 111111: 251

### Method 2: Block Size

- Block Size: 255.255.255.255
- Subnet Mask: 255.255.255.248
- Result: 7
- \(202 / 8\)

### Example Network Address Calculation

- IP: 172.20.200.102
- Subnet Mask: 255.255.224.0
- NID bit: 1
- HID bit: 0

### Calculation

- Subnet Mask: 255.255.255.192
- Bits: 8, 8, 8
- Calculate HID: \(2^{10} = 1024\), \(2^{13} = 8192\)
- HID = 13, NID = 32 - 13 = 19

{11111111.11111111.111}{0000.00000000} = 255.255.255.0

Here's a concise summary of the key points you provided about networking concepts, particularly regarding IP addressing, NAT, CIDR, routing, and protocols:

### IANA and IP Addressing

- **IANA (Internet Assigned Numbers Authority)**: Responsible for allocating IP addresses globally, including assigning ranges for private and public use.

### IP Address Classes

- **Private IP Ranges**:
  - **Class A**: 10.0.0.0 - 10.255.255.255
  - **Class B**: 172.16.0.0 - 172.31.255.255
  - **Class C**: 192.168.0.0 - 192.168.255.255
- **Public IP**: Assigned by ISPs for broader communication.

### Network Address Translation (NAT)

- **NAT**: Modifies IP address information in packet headers, allowing private IP addresses to communicate with the public network via a router.

### Classless Inter-Domain Routing (CIDR)

- **CIDR**: Allows for more efficient allocation of IP addresses, determining the number of network bits and helping with routing.

### Subnetting

- **Subnetting**: Divides a larger network into smaller, manageable segments to reduce IP wastage and enhance performance.
  - **FLSM (Fixed-Length Subnet Mask)** and **VLSM (Variable-Length Subnet Mask)**: Two approaches to subnetting.

### Default Gateway

- **Default Gateway**: The router IP that serves as an access point for devices to reach outside networks.

### Routing Concepts

- **Routing**: The process of determining the path data takes across a network.
  - **Static Routing**: Manually configured routes in the routing table.
  - **Dynamic Routing**: Automatically adjusts routes based on network changes.

### Commands for Network Configuration

- In a router configuration:
  ```bash
  router rip
  version 2
  network {connected-ip}
  ```

### Example of IP Addressing and Subnetting

1. **Given IP**: `172.19.50.100/26`

   - **Subnet Mask**: `255.255.255.192`
   - **Subnetting Calculation**:
     - Network address: `172.19.50.0`
     - Broadcast address: `172.19.50.63`
     - Valid IPs: `172.19.50.1` to `172.19.50.62`

2. **Network Address and Broadcast Address Calculation**:
   - For `192.168.10.0/24`:
     - Network Address: `192.168.10.0`
     - Broadcast Address: `192.168.10.255`

### RIP (Routing Information Protocol)

- **RIP**: An older routing protocol used for determining the best path based on hop count.
- Configuration commands:
  ```bash
  router rip
  version 2
  network {connected-ip}
  ```

### General Notes

- **Subnet Masks**: Define the portion of an IP address that is the network ID versus the host ID.
- **Wildcard Masks**: Used in routing protocols to specify which bits of an IP address to match.
- **ARP Table**: Maintained by devices to map IP addresses to MAC addresses for local communications.

### Network Security and IPv6 Overview

#### Types of Attacks

- **Passive Attacks**: These involve the attacker monitoring data transmissions without altering them. Examples include:

  - **Eavesdropping**: Listening to data being transmitted.
  - **Monitoring**: Observing network traffic for sensitive information.

- **Active Attacks**: These involve direct manipulation of data. The attacker alters the communication or data packets. Examples include:
  - Data tampering
  - Replay attacks

#### Network Address Translation (NAT)

NAT is a technique used to convert private IP addresses to public IP addresses and vice versa. It allows multiple devices on a local network to share a single public IP address when accessing the internet. This provides an additional layer of security and helps conserve IP address space.

#### End-to-End Encryption

End-to-end encryption (E2EE) is a secure communication method where data is encrypted on the sender's device and only decrypted on the recipient's device. This ensures that intermediaries cannot read the message, thereby enhancing security.

---

### IPv6 Overview

#### Key Features

- **Hexadecimal Representation**: IPv6 addresses are expressed in hexadecimal, making them more compact than IPv4.
- **Size**: IPv6 addresses are 128 bits long, allowing for a vastly larger number of hosts (2^128).
- **No Need for NAT**: The large address space eliminates the necessity for NAT.
- **Address Structure**: An IPv6 address consists of 8 groups of 4 hexadecimal digits, separated by colons (:). For example:
  - Full address: `3001:0cbd:95a3:8ae2:0000:0370:7334`
  - Compressed form: `3001:ocbd:95a3:8ae2::0370:7334` (using "::" to denote leading zeros).

#### Stateless Address Autoconfiguration (SLAAC)

SLAAC allows devices to automatically generate their own IPv6 addresses without requiring a DHCP server. This simplifies network setup and reduces manual configuration efforts.

---

### Router Configuration CLI for IPv6

Here's a typical command-line interface (CLI) setup for configuring IPv6 on a router:

```bash
Router> en                       # Enable privileged EXEC mode
Router# conf t                   # Enter global configuration mode
Router(config)# ipv6 unicast-routing  # Enable IPv6 routing

# Configure Gigabit Ethernet Interface 0/0
Router(config)# interface Gig0/0
Router(config-if)# ipv6 address FE80::1 link-local  # Assign link-local address
Router(config-if)# no shut                           # Activate the interface

Router(config-if)# ipv6 address 2001:DB43:AAAA:A::1/64  # Assign global unicast address
Router(config-if)# no shut                             # Activate the interface

# Configure Gigabit Ethernet Interface 0/1
Router(config)# interface Gig0/1
Router(config-if)# ipv6 address 2001:DB43:AAAA:B::1/64  # Assign global unicast address
Router(config-if)# no shut                             # Activate the interface
```

### Client Configuration for IPv6

On PCs, ensure that IPv6 is set to automatic to allow devices to use SLAAC for address configuration.

### Overview of DHCP and CIDR

#### Classless Inter-Domain Routing (CIDR)

- **Definition**: CIDR is a method for allocating IP addresses that improves efficiency in IP address usage compared to the traditional class-based addressing system.
- **Key Features**:
  - Allows for variable-length subnet masking (VLSM).
  - Reduces wastage of IP addresses by allowing more granular allocation of IP blocks.

#### Dynamic Host Configuration Protocol (DHCP)

- **Definition**: DHCP is a network protocol that automates the assignment of IP addresses and other configuration parameters to devices on a network.
- **Components**:
  - **DHCP Server**: Responsible for assigning IP addresses and network configuration parameters. It manages the IP address pool and leases addresses to clients.
  - **DHCP Client**: A device (like a computer or smartphone) that requests an IP address from the DHCP server.
  - **IP Address Pool**: A range of IP addresses available for assignment to devices on a network, managed by the DHCP server.

#### DHCP Options

DHCP can provide several parameters to clients, including:

- **Subnet Mask**: Defines the network's subnetting scheme.
- **Default Gateway**: The router IP address that devices use to access external networks.
- **DNS Server**: Translates domain names into numeric IP addresses, allowing devices to resolve hostnames.
- **Domain Name**: Additional configuration for the client.

#### DHCP Modes

1. **Automatic Allocation**: The DHCP server assigns a permanent IP address to the client.
2. **Dynamic Allocation**: The DHCP server assigns an IP address for a limited time (lease period).

#### Advantages of DHCP

- **Automation**: Simplifies IP address management by automating the assignment process.
- **Reduction of Errors**: Minimizes configuration mistakes by centralizing IP address management.
- **Efficient Use of IP Addresses**: Optimizes the allocation of IP addresses, reducing waste.
- **Scalability**: Easily accommodates a large number of devices in a network.

#### Disadvantages of DHCP

- **Security Risks**: Unauthorized devices can potentially obtain IP addresses if proper security measures are not in place.
- **Single Point of Failure**: If the DHCP server fails, clients cannot obtain IP addresses, disrupting network access.

---

### DHCP Server Configuration Example

Here’s an example of how to configure a DHCP server on a Cisco router:

bash
hostname dhcp-server
interface Gig0/0
ip address 192.168.1.1 255.255.255.0 # Configure the first interface
no shutdown

interface f0/1
ip address 192.168.2.1 255.255.255.0 # Configure the second interface
no shutdown

# Show all IP interfaces

do show ip interface brief

# Exclude specific addresses from DHCP pool

ip dhcp excluded-address 192.168.3.1 # Exclude an address already assigned
ip dhcp excluded-address {ip_address} # Replace with actual IPs to exclude

# Configure the first DHCP pool

ip dhcp pool Pool1
network 192.168.1.0 255.255.255.0
default-router 192.168.1.1 # Set the default gateway
dns-server 8.8.8.8 # Set the DNS server

# Configure the second DHCP pool

ip dhcp pool Pool2
network 192.168.3.0 255.255.255.0
default-router 192.168.3.1 # Set the default gateway
dns-server 8.8.8.8 # Set the DNS server

Here's a detailed explanation of each topic you mentioned:

### DNS Resolution

- **Definition**: DNS (Domain Name System) resolution is the process of converting user-friendly domain names (like www.example.com) into machine-readable IP addresses (like 192.0.2.1) that computers use to identify each other on the network.
- **Process**:
  1. **User Request**: A user enters a domain name in their browser.
  2. **DNS Query**: The browser sends a DNS query to a DNS resolver.
  3. **Recursive Resolution**: If the resolver doesn't have the IP cached, it queries the authoritative DNS servers, starting from the root servers, moving to TLD servers, and finally to the authoritative server for the domain.
  4. **IP Address Response**: The authoritative server responds with the corresponding IP address, which the resolver sends back to the user's browser.
  5. **Connection Establishment**: The browser can now use the IP address to connect to the web server.

### Network Traffic Capture

- **Definition**: Network traffic capture involves monitoring and recording the data packets that traverse a network. This can be done using tools like Wireshark, tcpdump, or similar software.
- **Purpose**:
  - **Troubleshooting**: Identifying network issues or failures.
  - **Security Analysis**: Detecting unauthorized access or malicious activities.
  - **Performance Monitoring**: Assessing network performance and bottlenecks.

### Flags in Communication

- **Definition**: Flags are specific bits in TCP segments that indicate the status and control information of a TCP connection. Common flags include:
  - **SYN**: Synchronize, used to initiate a connection.
  - **ACK**: Acknowledgment, used to acknowledge the receipt of packets.
  - **FIN**: Finish, used to close a connection.
  - **RST**: Reset, used to abort a connection.

### TCP Three-Way Handshake

- **Definition**: The TCP three-way handshake is a method used to establish a connection between a client and server before data transfer.
- **Steps**:
  1. **SYN**: The client sends a SYN packet to the server to request a connection.
  2. **SYN-ACK**: The server responds with a SYN-ACK packet, acknowledging the request and sending its own request to establish a connection.
  3. **ACK**: The client sends an ACK packet back to the server, completing the handshake. The connection is now established.

### Access Control Lists (ACLs)

- **Definition**: ACLs are rules that determine which users or systems can access specific resources in a network or operating system.
- **Functionality**:
  - Specify allowed or denied actions for users or systems on various resources.
  - Can be implemented on routers, firewalls, and operating systems.
- **Whitelisting vs. Blacklisting**:
  - **Whitelisting**: A security approach where only explicitly listed entities (IP addresses, applications, users) are granted access. Everything not on the list is denied.
  - **Blacklisting**: A security measure that denies access to specified entities, allowing all others. It's a reactive approach focusing on known threats.

### Top-Level Domain (TLD)

- **Definition**: A TLD is the last segment of a domain name, appearing after the final dot. For instance, in the domain name www.example.com, the TLD is .com.
- **Types of TLDs**:
  - **Generic TLDs (gTLD)**: e.g., .com, .org, .net.
  - **Country Code TLDs (ccTLD)**: e.g., .uk, .de, .jp.

### Filtering IP Addresses

- **Examples of Filtering**:
  - **ip.addr**: Used to filter packets based on any IP address (source or destination).
  - **ip.src**: Filters packets where the specified IP address is the source.
  - **ip.dst**: Filters packets where the specified IP address is the destination.

### Network Devices Representation

- **Routers**: Typically represented by a circle with an “X” inside, indicating their role in directing traffic between networks.
- **Hubs**: Often depicted as a square, representing a simple device that connects multiple devices in a network without any traffic management.

### hping3

- **Definition**: hping3 is a command-line tool used for network testing and security auditing. It can send custom TCP/IP packets and analyze responses, useful for various network tasks such as firewall testing and advanced packet crafting.

### Web Crawlers

- **Definition**: Web crawlers (or spiders) are automated programs that systematically browse the web to index content for search engines. They collect information about web pages to help in search engine optimization and content indexing.

### Network Discovery Tools

- **netdiscover**: A network scanning tool that helps identify live hosts in a network.
  - **Command**: `netdiscover -I eth0` scans the specified interface (eth0) for devices.
  - **Note**: It may not show its own IP address in the results, as it focuses on discovering other devices.

### Mitigation Strategies

- **Definition**: Mitigation refers to actions taken to minimize the impact of potential threats or attacks on a network.
- **Examples**: Implementing firewalls, intrusion detection systems, and regular software updates.

### Nmap Usage

- **Definition**: Nmap (Network Mapper) is a powerful tool for network exploration and security auditing.
- **Common Commands**:
  - `nmap 10.0.2.0-255`: Scans a range of IP addresses.
  - `nmap -sn`: Performs a ping scan without port scanning.
  - `nmap <ip> -O`: Detects the operating system of the target.
  - `nmap <ip> -A`: Provides detailed information about the target, including service versions and operating system detection.
  - `nmap <target-ip> -sV`: Scans for service versions on open ports.

### Passive vs. Active Information Gathering

- **Passive Information Gathering**: Collecting data about a target without directly interacting with it, such as using public records or social engineering.
- **Active Information Gathering**: Engaging with the target directly to obtain information, often using tools and techniques that may alert the target.

### Wireshark Commands

- **Common Filtering Commands**:
  - `ip.src`: Filters packets by source IP address.
  - `ip.dst`: Filters packets by destination IP address.
  - `ip.addr`: Filters packets by any IP address (source or destination).
  - `tcp.port == 443`: Filters packets on TCP port 443 (HTTPS).
  - `tcp.analysis.flags`: Displays TCP packets with analysis flags.
  - `!(ARP or dns or icmp)`: Excludes ARP, DNS, and ICMP packets from the display.
  - `tcp contains "facebook"`: Filters TCP packets that contain the string "facebook".
  - `http.request`: Filters HTTP request packets.
  - `http.responsecode == 200`: Filters HTTP response packets with a status code of 200 (OK).

---
