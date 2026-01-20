# Networking Basics for Cyber Security

## Project Overview
This project focuses on understanding **basic networking concepts** and performing
**network traffic analysis** using **Kali Linux** and **Wireshark**.
The objective is to learn how data travels across a network and how
network traffic is analyzed from a cyber security perspective.

---

## Tools & Environment
- **Operating System:** Kali Linux (VMware)
- **Primary Tool:** Wireshark
- **Alternative Tools:** tcpdump, Microsoft Network Monitor

---

## Networking Concepts Explained
- **IP Address:** Unique identifier of a device on a network  
- **MAC Address:** Hardware address of a network interface  
- **DNS:** Converts domain names into IP addresses  
- **TCP:** Reliable, connection-oriented protocol  
- **UDP:** Fast, connectionless protocol  
- **TCP Three-Way Handshake:** SYN → SYN-ACK → ACK  
- **HTTP:** Unencrypted web communication  
- **HTTPS:** Secure, encrypted web communication  
- **Packet Sniffing:** Capturing and analyzing network packets  

---

## Practical Tasks Performed
- Installed Wireshark on Kali Linux
- Captured live network traffic
- Applied protocol filters (TCP, UDP, DNS, HTTP, TLS)
- Observed TCP three-way handshake
- Analyzed DNS queries and responses
- Compared plain-text and encrypted traffic

---

# What is a Network?

A network is a group of devices (computers, phones, servers) connected together so they can share data.
A network is not just devices connected together.
It is a system of communication rules that allows devices to send, receive, and verify data.

Example:
- Your laptop connected to Wi-Fi
- Mobile phone connected to the internet

In cyber security:
- Attackers target networks to steal data
- Defenders monitor networks to detect threats

Every cyber attack travels through a network.

---

# What is Network Traffic?

Network traffic is the data that moves from one device to another over a network.

Example:
- Opening a website
- Sending a message
- Downloading a file

Traffic includes:
- Normal user activity (browsing, emails)
- Background services (updates, syncing)
- Malicious activity (malware, attacks)

Cyber security professionals analyze traffic to:
- Find abnormal behavior
- Detect hidden attacks

---

# What is Packet?

A packet is a small piece of data sent over a network.
Big data is broken into small packets, sent separately, and then reassembled at the destination.
A packet is a structured unit of data.

Each packet contains:
- Source address (who sent it)
- Destination address (who receives it)
- Protocol information
- Actual data

Packets are like letters in envelopes sent through the internet.

---

# What is Packet Sniffing?

Packet sniffing means capturing and analyzing network packets.

There are two sides:
- Defensive: Detect attacks and troubleshoot
- Offensive: Steal data (illegal without permission)

Ethical hackers use packet sniffing to:
- Test network security
- Identify weak encryption
- Detect data leakage

---

# What is Wireshark?

Wireshark is a network packet analyzer.Wireshark does not create traffic — it observes it.

Wireshark is a core SOC tool.

It allows us to:
- Capture live network traffic
- View packets in detail
- Analyze protocols
- Detect security issues

---

# What is IP Address?

An IP address is a unique number given to a device on a network.
- Example: 192.168.1.10

An IP address acts as both:
- Identity (who you are)
- Location (where you are)

In cyber security:
- Identifies sender and receiver
- IPs help track attackers
- IP reputation is used in firewalls
- Suspicious IPs are blocked
  
---

# What is MAC Address?

A MAC address is a unique hardware address of a network card.

Example:

00:1A:2B:3C:4D:5E

## Why important?
- Used in local networks
- Targeted in ARP attacks
- Can be spoofed by attackers

Security teams monitor MAC behavior to detect intrusions.


Difference:
- IP can change
- MAC usually does not change

---

# What is DNS?

DNS (Domain Name System) converts domain names into IP addresses.

Example:

google.com → 142.250.183.14

Cyber security risk:
- DNS poisoning
- Malware command-and-control
- Data exfiltration via DNS

SOC teams monitor DNS traffic carefully.


Without DNS, we would need to remember IP addresses.

---

# What is TCP?

TCP (Transmission Control Protocol) is a reliable communication protocol.

Features:
- Ensures data reaches correctly
- Sends data in order
- Checks for errors

Before sending data:
- It verifies connection
- It checks readiness
- ensures delivery

TCP is preferred for:
- Sensitive data
- Login sessions
- File transfers

Used by:
- HTTP
- HTTPS
- FTP
- SSH

---

# What is TCP Three-Way Handshake?

The TCP handshake is the process used to create a connection.

Steps:

1.SYN – Client asks to connect

2.SYN-ACK – Server agrees

3.ACK – Client confirms

This ensures a secure and reliable connection.

Attack detection:
- SYN flood attacks abuse this process

Wireshark shows handshake clearly.

---

# What is UDP?

UDP (User Datagram Protocol) is a fast but unreliable protocol.

Features:
- No connection setup
- No guarantee of delivery
- Very fast

Used by:
- DNS
- Video streaming
- Online games

Security risk:
- Easy to abuse
- Common in DDoS attacks

Defenders monitor abnormal UDP spikes.

---

| TCP                 | UDP               |
| ------------------- | ----------------- |
| Reliable            | Fast              |
| Connection-oriented | Connectionless    |
| Error checking      | No error checking |
| Slower              | Faster            |

---

# What is HTTP?

HTTP (Hypertext Transfer Protocol) is used to transfer web data.HTTP sends data in plain text.

Security problem:
- Password sniffing
- Session hijacking
- Data leakage

HTTP should never be used for sensitive data.

Problem:
- Data is not encrypted
- Anyone can read the data

---

# What is HTTPS?

HTTPS is the secure version of HTTP.HTTPS adds encryption and authentication.

Benefits:
- Data confidentiality
- Data integrity
- Trust verification

TLS protects users from attackers.

Features:
- Uses encryption (SSL/TLS)
- Protects data
- Prevents data theft

---

## Why HTTPS is More Secure than HTTP?

Because HTTPS encrypts data, making it unreadable to attackers.

---

# What is Encryption?

Encryption converts readable data into unreadable form.

Only authorized users can decrypt and read it.

Encryption ensures:
- Only intended users read data
- Attackers see meaningless data

Used everywhere:
- HTTPS
- VPNs
- Secure emails

---

# What is a PCAP File?

A PCAP file is a file that stores captured network packets.PCAP is a recording of network traffic.

Used in:
- Incident response
- Malware analysis
- Legal investigations

PCAPs are digital evidence.

Used for:
- Traffic analysis
- Digital forensics
- Security investigations

---

# What is Kali Linux?

Kali Linux is a Linux operating system designed for cyber security.Kali Linux is a security testing environment.

Includes:
- Network tools
- Forensic tools
- Exploitation frameworks

Used by professionals worldwide.

Used for:
- Penetration testing
- Network analysis
- Ethical hacking

---

# What is Virtual Machine (VMware)?

A virtual machine is a computer inside your computer.

Virtual machines provide:
- Isolation
- Safety
- Repeatable labs

Essential for security training.

VMware allows us to:
- Run Kali Linux safely
- Practice cyber security labs

---

What is Network Interface?

A network interface is a connection point to a network.network interface is how data enters or exits a system.

Security monitoring focuses on:
- Active interfaces
- Unauthorized traffic

Examples:
- eth0 (wired)
- wlan0 (wireless)

---

# What is Filtering in Wireshark?

Filtering means showing only specific packets.

Filters allow analysts to:
- Reduce noise
- Focus on threats
- Identify patterns

Filtering is a core SOC skill.

Examples:
- dns
- tcp
- http
- tls

---

# What is Network Analysis?

Network analysis helps:
- Detect intrusions
- Identify malware
- Monitor compliance

It is a first line of defense.

Network analysis is the process of examining traffic to:
- Understand communication
- Detect suspicious activity
- Improve security

---

# Why Network Analysis is Important in Cyber Security?

Because:
- Attacks leave network traces
- Helps detect malware
- Helps prevent data breaches

---

# Final Outcome of This Task

After completing this task, you can:
- Understand how data travels on a network
- Analyze packets using Wireshark
- Identify secure and insecure traffic
- Answer interview questions confidently

---

# Now Move on PRACTICAL
Platform: VMware + Kali Linux
- Level: Beginner → Intermediate
- Outcome: Hands-on + Interview-ready

--- 

## STEP 01
- VMware installed
- Kali Linux VM running
- Internet working inside Kali
    
-- ping google.com
If you see replies → internet is working

---

## STEP 02: Update Kali Linux
Open Terminal and run:

-- sudo apt update

Why?
- Updates package list
- Prevents installation errors

---

## STEP 03: Install Wireshark
--sudo apt install wireshark -y

Important Question During Install
You will see:

Allow non-superusers to capture packets?
Select YES

### Why?
- Safer than running Wireshark as root
- Follows security best practice

---

## STEP 04
open Wireshark-Wireshark home screen showing interfaces

---

## STEP 05
Identify Network Interface
You will see interfaces like:
- eth0 → wired / VMware NAT
- wlan0 → wireless

Usually eth0 is active in VMware.

--Click on eth0

---

## STEP 06: Start Packet Capture

Once you click the interface:
- Capture starts automatically
- Packets begin appearing

--You are now sniffing your own traffic

---

## STEP 07: Generate Network Traffic
Open Firefox or Browser in kali and visit website like :
- https://www.gooogle.com
- https://www.youtube.com
- https://www.instagram.com

This creates:
- DNS traffic
- TCP traffic
- HTTPS traffic

---

## STEP 08: Understand Wireshark Layout
Wireshark has 3 panels:
- 1 Packet List – All packets
- 2️ Packet Details – Layer-wise info
- 3️ Packet Bytes – Raw data

Click any packet → details appear below.

Showing packets + packet details

---

## STEP 09: Apply Basic Filters
Filter DNS Traffic

In filter bar:

--dns


You will see:
- Domain names
- DNS queries and responses

### Filter TCP Traffic

---tcp

Shows:
- Reliable connections
- Handshakes
- Data transfer

### Filter UDP Traffic

---udp

Fast, connectionless traffic

### Filter HTTPS Traffic
--tls

Payload is encrypted → unreadable - Data is encrypted → cannot read content

### Filter HTTP (if Avilable)
---http

Then:
Right-click packet → Follow → TCP Stream

---Data may be readable.

| Purpose           | Filter               |
| ----------------- | -------------------- |
| DNS traffic       | `dns`                |
| TCP packets       | `tcp`                |
| UDP packets       | `udp`                |
| TCP handshake     | `tcp.flags.syn == 1` |
| Encrypted traffic | `tls`                |


# STEP 10: Observe TCP Three-Way Handshake
Apply filter:

---tcp.flags.syn == 1

You will see:
- SYN
- SYN-ACK
- ACK

Click each packet and look at Flags.

---


# Interview Questions – Networking & Wireshark
Q.1. What is TCP Handshake ?

Answer:

TCP three-way handshake is a connection-establishment mechanism that ensures both client and server are ready for reliable data transmission.

Steps:
- SYN - 
Client sends SYN packet with initial sequence number.

- SYN-ACK - 
Server acknowledges client’s SYN and sends its own sequence number.

- ACK - 
Client acknowledges server’s sequence number.

### Why required?
- Confirms both devices are reachable
- Prevents half-open connections
- Synchronizes sequence numbers
- Ensures reliable communication
- Without handshake, data loss and spoofing risks increase.

Q.2. Difference between TCP and UDP ?

Answer :

TCP (Transmission Control Protocol)
A reliable, connection-oriented protocol that ensures data is delivered correctly and in order.

UDP (User Datagram Protocol)
A fast, connectionless protocol that sends data without guaranteeing delivery.

| Feature         | TCP                 | UDP            |
| --------------- | ------------------- | -------------- |
| Connection Type | Connection-oriented | Connectionless |
| Reliability     | Reliable            | Unreliable     |
| Packet Order    | Maintained          | Not maintained |
| Speed           | Slower              | Faster         |
| Error Recovery  | Yes                 | No             |
| Header Size     | Large               | Small          |

TCP is reliable and connection-oriented, ensuring ordered and guaranteed delivery, whereas UDP is fast and connectionless, prioritizing speed over reliability.

Q.3. What is DNS ?

Answer : DNS is a system that translates domain names into IP addresses so computers can locate each other on the internet.

Q.4. What is Packet Sniffing ?

Answer : Packet sniffing is the process of capturing and analyzing network packets to monitor communication or detect security issues.

Q.5. Why is HTTPS more Secure than HTTP ?

Answer : HTTPS is more secure than HTTP because it uses SSL/TLS encryption to ensure confidentiality, integrity, and authentication. This protects data from interception, tampering, and impersonation attacks.

Encryption (Most Important)
- HTTP sends data in plain text
- HTTPS encrypts data using SSL/TLS

--Even if an attacker captures packets, they cannot read the data

Example:
- HTTP → username=admin&password=1234
- HTTPS → x9aF3$@#%… (encrypted)



