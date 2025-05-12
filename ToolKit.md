# IT System Admin Tests Toolkit
*By Mark McDow — My Computer Guru, LLC*

A categorized reference for validating systems, endpoints, security, and connectivity.

---

## 1. Antivirus / Malware Detection

- **EICAR Test File:** https://www.eicar.org/?page_id=3950
- **AMTSO Browser Tests:** https://www.amtso.org/security-features-check/
- **Sample Malicious Links (safe simulations)**

---

## 2. Network & Internet Connectivity

- Ping: `ping 1.1.1.1`, `ping 8.8.8.8`
- DNS: `nslookup google.com`
- HTTP: `Invoke-WebRequest https://www.msftconnecttest.com/connecttest.txt`
- Captive Portal: `http://www.msftncsi.com/ncsi.txt`

---

## 3. Content Filtering & DNS

- **OpenDNS Test Page:** http://internetbadguys.com
- **DNSFilter Test Pages:** https://test.dnsfilter.com/
- **NextDNS:** https://test.nextdns.io/

---

## 4. Email Security & SMTP Testing

- **MXToolbox:** https://mxtoolbox.com/diagnostic.aspx
- **Telnet SMTP Test:** `telnet mail.example.com 25`
- **DMARC Checkers:** dmarcanalyzer.com, MXToolbox SuperTool
- **SPF/DKIM/DMARC:** `spf:yourdomain.com`, etc.

---

## 5. Blacklist / RBL Checks

- https://mxtoolbox.com/blacklists.aspx
- https://multirbl.valli.org/lookup/
- https://check.spamhaus.org/

---

## 6. SSL/TLS Certificate & Web Security

- **SSL Labs:** https://www.ssllabs.com/ssltest/
- **Hardenize:** https://www.hardenize.com/
- **CheckTLS:** https://www.checktls.com/
- **BadSSL:** https://badssl.com/

---

## 7. Authentication, Identity, and Policy

- Test MFA prompts
- Password policy enforcement
- https://haveibeenpwned.com/
- Microsoft Secure Score

---

## 8. Logging / Endpoint / SIEM

- Simulate login failures
- USB insert/removal logs
- Confirm ingestion into SIEM

---

## 9. Web App Headers & Security

- https://securityheaders.com/
- https://observatory.mozilla.org/

---

## 10. Port & Service Discovery

- **Nmap / Zenmap**
- `nmap -sV -Pn target.com`
- **Shodan:** https://shodan.io/

---

## 11. Backups & DR

- Simulate data loss
- Perform restore test
- Monitor logs and test alerts

---

## 12. RDP & Remote Access

- Lockout policies
- Monitor brute force attempts
- `quser` / `qwinsta` in PowerShell

---

## 13. Patch & Deployment Checks

- Verify Intune/SCCM pushes
- Validate auto-update of major apps

---

## 14. User Awareness / Phishing

- Gophish or KnowBe4 simulation
- Metrics: clicks, opens, reports

---

## 15. Certificate Expiration & Internal PKI

- Check expiry on all SSL endpoints
- Track AD CS internal certs

---

## 16. Misc Tools

- **CIS CAT Lite:** https://www.cisecurity.org/cis-cat-lite/
- **Microsoft SCT:** https://learn.microsoft.com/en-us/windows/security/threat-protection/
- **Wireshark, PingPlotter, Netcat**

---

## 17. Domain & DNS Investigation Tools (Free)

### **Command Line Tools**

- `nslookup domain.com` – General DNS queries (Windows)
- `dig domain.com ANY` – Detailed DNS records (Linux/macOS/WSL)
- `whois domain.com` – Get domain ownership, expiration, registrar
- `host -t mx domain.com` – View MX records (Linux/macOS)
- `tracert` (Windows) / `traceroute` (Linux/macOS) – Route to destination

### **Free Online Tools**

- **[MXToolbox](https://mxtoolbox.com/):** MX, A, SPF, DKIM, DMARC, blacklist, SMTP diagnostics
- **[IntoDNS](https://intodns.com/):** DNS health check with glue, SOA, NS errors
- **[ViewDNS.info](https://viewdns.info/):** WHOIS, propagation check, traceroute, reverse IP lookup
- **[DNSViz](http://dnsviz.net/):** DNSSEC and DNS record graphing and validation
- **[SecurityTrails](https://securitytrails.com/):** WHOIS, DNS history, subdomain discovery (free account)
- **[ICANN Lookup](https://lookup.icann.org/):** Official WHOIS record from the domain registrar
- **[Google Admin Toolbox Dig](https://toolbox.googleapps.com/apps/dig/):** Fast web-based dig command
- **[DNS Checker](https://dnschecker.org/):** Global DNS propagation check for records like A, MX, CNAME

---

## Appendix

- PowerShell test scripts
- Bash test scripts
- Offline PDF printout version
---

## 18. Manual Testing of Mail and Other Protocols

### **SMTP (Send Email via Telnet)**

```bash
telnet mail.example.com 25
EHLO example.com
MAIL FROM:<test@example.com>
RCPT TO:<user@example.com>
DATA
Subject: Test Email

This is a test.
.
QUIT
```

### **POP3 (Retrieve Email via Telnet)**

```bash
telnet mail.example.com 110
USER yourusername
PASS yourpassword
LIST
RETR 1
QUIT
```

### **IMAP (Check Mail via Telnet or OpenSSL)**

```bash
openssl s_client -connect mail.example.com:993
a login yourusername yourpassword
a list "" "*"
a select inbox
a fetch 1 body[header]
a logout
```

> IMAP typically uses SSL on port 993, so OpenSSL is better than Telnet for testing.

---

### **Other Manually Testable Protocols**

| Protocol | Default Port | Test Method |
|----------|--------------|-------------|
| **FTP**  | 21           | `ftp server` or `telnet server 21` |
| **HTTP** | 80           | `telnet site.com 80` and send `GET / HTTP/1.1` |
| **HTTPS**| 443          | `openssl s_client -connect site.com:443` |
| **SSH**  | 22           | `ssh user@host` or `telnet host 22` to confirm port open |
| **DNS**  | 53           | `nslookup`, `dig`, or `host` |
| **RDP**  | 3389         | `Test-NetConnection -Port 3389` (Windows) |
| **LDAP** | 389 / 636    | `ldp.exe` on Windows or `ldapsearch` (Linux) |
| **SMB**  | 445          | `net use \\host\share` (Windows) or `smbclient` (Linux) |
| **NTP**  | 123          | `w32tm /stripchart /computer:time.windows.com` or `ntpq -p` |

---

### **Useful Built-in or Free Tools**

- `Test-NetConnection` (PowerShell)
- `telnet` (enable via Windows Features)
- `openssl s_client` (for SSL/TLS and IMAP/SMTP testing)
- `nmap` for port scanning and banner grabbing
- `netcat` (`nc`) for raw socket connections (Linux/macOS/WSL)
- `curl` and `wget` for HTTP/S and FTP file tests

