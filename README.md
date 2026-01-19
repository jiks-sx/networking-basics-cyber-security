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
- Saved packet capture files for analysis

---

# What is a Network?

A network is a group of devices (computers, phones, servers) connected together so they can share data.

Example:
- Your laptop connected to Wi-Fi
- Mobile phone connected to the internet

---

# What is Network Traffic?

Network traffic is the data that moves from one device to another over a network.

Example:
- Opening a website
- Sending a message
- Downloading a file

---

# What is Packet?

A packet is a small piece of data sent over a network.
Big data is broken into small packets, sent separately, and then reassembled at the destination.

---

# What is Packet Sniffing?

Packet sniffing means capturing and analyzing network packets.

Used for:
- Network troubleshooting
- Cyber security analysis
- Detecting attacks

---

# What is Wireshark?

Wireshark is a network packet analyzer.

It allows us to:
- Capture live network traffic
- View packets in detail
- Analyze protocols
- Detect security issues

---

# What is IP Address?

An IP address is a unique number given to a device on a network.
- Example: 192.168.1.10

Purpose:
- Identifies sender and receiver
- Helps data reach the correct device
  
---

# What is MAC Address?

A MAC address is a unique hardware address of a network card.

Example:

00:1A:2B:3C:4D:5E


Difference:
- IP can change
- MAC usually does not change

---

# What is DNS?

DNS (Domain Name System) converts domain names into IP addresses.

Example:

google.com → 142.250.183.14


Without DNS, we would need to remember IP addresses.

---

# What is TCP?

TCP (Transmission Control Protocol) is a reliable communication protocol.

Features:
- Ensures data reaches correctly
- Sends data in order
- Checks for errors

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

---

| TCP                 | UDP               |
| ------------------- | ----------------- |
| Reliable            | Fast              |
| Connection-oriented | Connectionless    |
| Error checking      | No error checking |
| Slower              | Faster            |

---

# What is HTTP?

HTTP (Hypertext Transfer Protocol) is used to transfer web data.

Problem:
- Data is not encrypted
- Anyone can read the data

---

# What is HTTPS?

HTTPS is the secure version of HTTP.

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

---

# What is a PCAP File?

A PCAP file is a file that stores captured network packets.

Used for:
- Traffic analysis
- Digital forensics
- Security investigations

---

# What is Kali Linux?

Kali Linux is a Linux operating system designed for cyber security.

Used for:
- Penetration testing
- Network analysis
- Ethical hacking

---

What is Virtual Machine (VMware)?

A virtual machine is a computer inside your computer.

VMware allows us to:

Run Kali Linux safely

Practice cyber security labs
