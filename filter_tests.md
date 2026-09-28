# Question 3: Packet Filtering Firewall Configuration & Verification

## Firewall Rule Base Policy

| Rule ID | Direction | Source IP / Subnet | Destination IP | Protocol | Destination Port | Action | Purpose / Rationale |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **R1** | Inbound | `192.168.1.0/24` | `10.0.0.10` | TCP | 80 (HTTP) | **ALLOW** | Permit internal users to access public Web server. |
| **R2** | Inbound | `192.168.1.0/24` | `10.0.0.10` | TCP | 443 (HTTPS) | **ALLOW** | Permit secure encrypted web traffic. |
| **R3** | Inbound | `192.168.1.0/24` | `10.0.0.5` | UDP | 53 (DNS) | **ALLOW** | Enable domain name resolution for internal hosts. |
| **R4** | Inbound | Any (`0.0.0.0/0`) | `10.0.0.0/24` | TCP | 23 (Telnet) | **DENY** | Block insecure cleartext management traffic. |
| **R5** | Inbound | Any (`0.0.0.0/0`) | `10.0.0.0/24` | ICMP | Any (Echo) | **DENY** | Mitigate network reconnaissance and ping sweeps. |
| **R6** | Inbound | Any (`0.0.0.0/0`) | Any (`0.0.0.0/0`) | Any | Any | **DENY** | Explicit implicit deny-all rule for defense-in-depth. |

---

## Linux `iptables` Implementation Script

```bash
#!/bin/bash
# Clear existing rules
iptables -F
iptables -X

# Set default policies to DROP (Default Deny)
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# R1 & R2: Allow HTTP (80) and HTTPS (443) to Web Server
iptables -A FORWARD -s 192.168.1.0/24 -d 10.0.0.10 -p tcp --dport 80 -j ACCEPT
iptables -A FORWARD -s 192.168.1.0/24 -d 10.0.0.10 -p tcp --dport 443 -j ACCEPT

# R3: Allow DNS queries (53) to DNS Server
iptables -A FORWARD -s 192.168.1.0/24 -d 10.0.0.5 -p udp --dport 53 -j ACCEPT

# R4: Explicitly drop Telnet (23)
iptables -A FORWARD -p tcp --dport 23 -j DROP

# R5: Explicitly drop ICMP Echo requests
iptables -A FORWARD -p icmp --icmp-type echo-request -j DROP