# WebDAV Penetration Test

## Table of Contents

This document contains the following sections:
- Network Topology
- Red Team: Security Assessment, Exploitation, and Avoiding Detection
- Blue Team: Log Analysis & Attack Characterization
- Hardening: Proposed Alarms & Mitigation Strategies

## Network Toplogy

- Network Address Range: 192.168.1.0/24
- Netmask: 255.255.255.0
- Gateway: 192.168.1.1

![Diagram](https://github.com/aele1401/WebDav_Pentest/blob/main/Images/RvB_Topology.PNG)

## Red Team: Security Assessment

### Recon: Describing the Target

- Nmap identified the following hosts on the network:
    * Azure Hyper-V ML serves as the host machine.
    * Kali as the attack machine.
    * Capstone as the target machine hosting an apache web server.
    * ELK machine that monitors changes to system metrics and logs that hosts Kibana.

|  Machine     |  IP Address   | Role on Network |
|--------------|---------------|-----------------|
|  Hyper-V ML  | 192.168.1.1   | Host Machine    | 
|  Kali        | 192.168.1.90  | Attack Machine  |
|  ELK         | 192.168.1.100 | ELK Machine     |
| Capstone     | 192.168.1.105 | Target Machine  |

### Vulnerability Assessment

- Assessment uncovered the following critical vulnerabilities:
    * **Open Ports (CAPEC-300)**: Port 80 is commonly used for web communication, and if left open, unsecure, with no security controls, it can be exploited.
        - Impact: 
            * Access to web server
            * Increased attack surface with services running on port to be exploited via SQL injection, XSS, or RCE.
            * Unencrypted traffic allows for MITM attacks where data can be intercepted.
            * Brute force or DDoS attacks maybe invited where web server can be overwhelmed with traffic reducing availability.
            * Regulatory and compliance issues. PCI DSS and HIPAA require encryption with transmitting sensitive data. Failing to secure port 80 with proper encryption could lead to compliance violations.
    * **Brute Force Attack & Insufficient Security Measures (CWE-307)**: An attack that consists of systematically checking all possible username and password combinations until the correct one is found.
        - Impact:
            * Improper controls implemented to prevent multiple failed login attempts.
            * Once attackers successfully guess valid credentials, they can log into the web application with the same privileges as the legitimate user, potentially escalating privileges or stealing sensitive data.
            * Since HTTP traffic is not encrypted on port 80, attackers can intercept the login attempts, decode the Base64-encoded credentials, and brute force the password without much difficulty.
            * Gaining access to an admin panel can allow an attacker to take full control of the web server or web application, modify content, or even execute commands on the server.
            * If they find unprotected directories, they might gain access to critical files, databases, or configuration settings, leading to further compromise.
    * **Simple User Names**: Short names, first names, or any simple combinations.
        - Impact:
            * Easily Guessable: Usernames like Ashton, Ryan, and Hannah are all simple usernames that can be easily obtained.
            * No Need for Discovery: If usernames are simple or follow predictable patterns (e.g., first names, email prefixes), attackers do not need to spend time or resources discovering valid usernames. This dramatically speeds up their brute force attempts, as they only need to focus on guessing the correct password once they have a valid username.
            * Default Usernames: Many web applications come with default usernames like "admin" or "root." Attackers know this, and these usernames are almost always the first ones targeted in brute force attacks.
            * Exposed to Enumeration Attacks: In some systems, attackers can use username enumeration techniques to discover whether a username exists. If a system responds differently for valid and invalid usernames (e.g., showing "Invalid password" for valid usernames and "Invalid username" for invalid usernames), attackers can quickly compile a list of valid usernames for the brute force attack.
            * Higher Success Rate: The simpler and more predictable the username, the easier it is for attackers to guess it, making brute force attacks far more likely to succeed.
            * Reduced Effort: Attackers can reduce the time and effort needed for reconnaissance and focus entirely on password guessing, increasing the speed of an attack.
    * **Weak Passwords**: Short, common, simple, or non-complex passwords.
        - Impact:
            * Easily Guessable: Weak passwords are often short, use simple patterns, or common words (e.g., "password," "123456," "qwerty"). These are easily cracked by attackers using brute force techniques or dictionary attacks, where automated tools try a large list of common passwords.
            * Reused Across Multiple Accounts: Many users tend to reuse weak passwords across multiple platforms. If one account is compromised, attackers may try the same password on other services, increasing the potential for widespread access.
            * Vulnerable to Brute Force Attacks: Weak passwords can be cracked very quickly by brute force tools. Tools like Hydra, John the Ripper, and others can try thousands of common or simple password combinations in seconds, especially for short or predictable passwords.
            * Data Theft: Access to sensitive information like personal data, business documents, or financial information.
            * System Compromise: An attacker can modify system settings, install malware, or further escalate privileges.
            * Lateral Movement: Once inside the network, an attacker can use the compromised account to move laterally to other systems.
    * **Directory Path Traversal (CWE-23)**: Improper access controls and filtering allowing access to restricted and hidden directories where attacks exploit improperly validated user input, especially when the input is used to specify file paths on the server. Attackers manipulate the file path parameters (e.g., `../` or `..\`) to move up the directory structure and access files beyond the intended scope.
        - Impact:
            * Allows unrestricted access to WebDAV directories.
            * Access to Sensitive Files: Attackers can read sensitive system files such as `/etc/passwd` (Linux) or `C:\Windows\System32\config\SAM` (Windows), which may contain user account information, password hashes, or other critical data.
            * Access to Configuration Files: Web server configuration files (e.g., `web.config`, `.htaccess`, or `wp-config.php`) may contain database credentials, API keys, or sensitive system settings that can further compromise the system.
            * Execution of Arbitrary Code: If the application allows file uploads or dynamic file generation, an attacker might be able to upload malicious files (e.g., PHP scripts) and execute them by traversing the directory structure to access and run these files.
            * Privilege Escalation: By gaining access to configuration files or sensitive system files, an attacker might escalate their privileges on the system, potentially gaining administrative or root access.
            * Denial of Service (DoS): In some cases, attackers can use directory traversal to overwrite important system files or delete crucial data, leading to a denial of service or complete system failure.
        - Example:
            * Consider a website that allows users to download reports through a URL parameter: `http://example.com/download?file=report.pdf`
            * If the application doesn’t validate or sanitize the input properly, an attacker could modify the URL: `http://example.com/download?file=../../../etc/passwd`
            * In this case, the attacker can access the `/etc/passwd` file (on Linux systems), which contains user account information, including encrypted passwords, thereby potentially gaining further access to the system.
    * **Hashed & Salted Passwords**: A salt is a random string added to a password before hashing it. This process ensures that even if two users have the same password, their hashes will be different, making it much harder for attackers to use precomputed hash tables (such as rainbow tables) to crack passwords.
        - Impact:
            * Password Hash Reuse: Without salts, identical passwords will produce identical hashes. If multiple users have the same password, all their hashes will be identical in the database, allowing an attacker to crack one and immediately know the passwords for all users with the same hash.
            * Rainbow Table Attacks: Rainbow tables are precomputed tables of common passwords and their corresponding hash values. If a database uses unsalted passwords, an attacker can simply compare the password hashes to those in the rainbow table to quickly reverse the hash back into the original password.
            * Dictionary Attacks: Even without a rainbow table, attackers can use dictionaries of common passwords to generate hashes and compare them to the stored hashes. This process is faster when passwords are unsalted because the attacker doesn’t need to handle the extra complexity of individual salts for each password.
            * Cracking Speed: The lack of a salt makes it easier and faster for attackers to crack large numbers of passwords simultaneously because they can use the same precomputed hashes or rainbow tables across multiple accounts.
        - Example:
            * Consider two users, Alice and Bob, both with the password "password123".
            * If the system uses unsalted hashes, both Alice and Bob will have the same hashed password stored in the database (e.g., `5e884898da28047151d0e56f8dc6292773603d0d` for a SHA-1 hash of "password123"). If an attacker cracks Alice's hash, they automatically know Bob's password too.
            * If the system uses salted hashes, even though Alice and Bob have the same password, the system generates unique salts (e.g., `a1b2c3` and `d4e5f6`) and stores hashed versions like:
                - Alice: `sha256(a1b2c3 + password123)`
                - Bob: `sha256(d4e5f6 + password123)`
            * In this case, the resulting hashes will be different, even though the passwords are the same, making it much harder for an attacker to crack both hashes.
    * **Local File Inclusion LFI (CAPEC-252)**: a type of web vulnerability that allows an attacker to trick the web application into exposing or executing files on the server. This vulnerability occurs when a web application dynamically includes files using user-supplied input without proper validation. If exploited, LFI can lead to sensitive data disclosure, code execution, privilege escalation, and even full system compromise. LFI vulnerabilities typically arise when a web application takes input from a user to determine which file to include or load on the server, and that input is not properly sanitized. Attackers can manipulate the input to gain access to local files that the web server shouldn't expose.
        - Impact:
            * Access to Sensitive Files: Attackers can read files on the server, such as configuration files, database credentials, password files, and logs, which can contain sensitive information, such as the `/etc/passwd` file which contains user account information, `wp-config.php` file that contains database credentials, and `log files` that contain sensitive information like session tokens and user activity logs.
            * Remote Code Execution (RCE): If an attacker can include files that the server executes (e.g., log files or uploaded files), they may be able to inject code that gets executed by the server, leading to remote code execution. For example, if an attacker can write to a log file and then include that file using LFI, they could potentially inject malicious code into the log and execute it.
            * Privilege Escalation: By reading sensitive configuration files or system files, attackers may be able to find information that allows them to escalate their privileges on the server. For example, they might find SSH private keys, credentials for admin accounts, or other sensitive information that allows them to gain further access to the system.
            * Chaining with Other Attacks: LFI is often used as a stepping stone in more complex attacks. For example, attackers may combine LFI with directory traversal to access files outside the web root, or with file upload vulnerabilities to execute arbitrary code. LFI can also be combined with session hijacking by including session files and extracting sensitive information from them.
        - Example:
            * An attacker might exploit LFI by manipulating a URL like this: `http://example.com/index.php?page=../../../../etc/passwd`
            * In this example, the attacker uses directory traversal (../) to move up the file directory hierarchy and access the /etc/passwd file, which contains sensitive system information.

### Exploitation: Web Port
* Nmap scan shows OS version, running services, and ports.
* 2 ports of interest:
    - Port 22 - SSH
    - Port 80 - Web
    - SSH with discovered credentials
    - Access web server

![Diagram](https://github.com/aele1401/WebDav_Pentest/blob/main/Images/NMAP.PNG)

### Exploitation: Brute Force User Accounts
* Obtain guessable usernames
* Hydra to brute force password
* Access to Ashton's user account
* Hashes for Ryan's account obtained through Ashton's compromised account
  
![Diagram](https://github.com/aele1401/WebDav_Pentest/blob/main/Images/Bruteforce.PNG)
![Diagram](https://github.com/aele1401/WebDav_Pentest/blob/main/Images/login.PNG)

### Directory Traversal
* URL parameter manipulation and pathname construction
* Access to restricted and hidden directories
* Access to confidential and proprietary data
  
![Diagram](https://github.com/aele1401/WebDav_Pentest/blob/main/Images/directory_traversal.png)

### Exploitation: Password Cracking
- Crackstation.net to crack Ryan's hashed password
- Ryan's account compromised
- Access to WebDAV directories
  
![Diagram](https://github.com/aele1401/WebDav_Pentest/blob/main/Images/crackstation.PNG)

### Exploitation: LFI Vulnerability
- Metasploit framework
    * MSF Venom and multihandler exploit tools to deliver a meterpreter shell payload
- Reverse shell uploaded on target machine
- Direct access to target machine
  
![Diagram](https://github.com/aele1401/WebDav_Pentest/blob/main/Images/meterpreter_shell.PNG)
![Diagram](https://github.com/aele1401/WebDav_Pentest/blob/main/Images/shell_php.png)

### Avoiding Detection - Port Scanning
- Stealth scans (SYN scan or decoy scanning by obfuscating the origin of a network scan by creating multiple fake source IP addresses)
- Slower scans by adjusting timing parameters
- Fragmentation by obscuring contents of packets
- Proxy chains and anonymization by rerouting scan traffic to obfuscate the source
- Protocol-based scanning using less common protocols like ICMP or SCTP

### Avoiding Detection - Enumeration
- Enumerating is noisy
- Stagger attempts
- Reduce scan intensity
- Passive enumeration techniques
- Stealthier scans, randomize timing, encrypt channels, and limit concurrent connections

### Avoiding Detection - Malware & Reverse Shells
- Alerts can be highly reliable
- Move laterally with SMB & Impackets
- Fileless Malware & Live of the Land techniques
- Evade detection through refactoring
- Obfuscation
- Request splitting
- User-agent spoofing
- IP address rotation
- Slow and Low technique
- Bypass logging
- Custom exploits (e.g., Metasploit)

## Blue Team: Log Analysis & Attack Characterization

### Analysis: Identifying the Port Scan
- Scans began on 05/04/2021 around 22:00 hours
- 51,185 connections originating from IP 192.168.1.90
- Sudden spikes and fluctuations in traffic indicates port scan
  
![Diagram](https://github.com/aele1401/WebDav_Pentest/blob/main/Images/connections_shot.PNG)

### Finding the Request for the Hidden Directory
- Web requests began at 18:00 hours on 05/04/2021
- 48,324 requests made to secret directory
- Directory contains password hashes for Ryan's account
- LFI allows for meterpreter shell payload to be uploaded
  
![Diagram](https://github.com/aele1401/WebDav_Pentest/blob/main/Images/HTTP_Requests.PNG)

### Analysis: Uncovering the Brute Force Attack
- 48,324 requests made
- Only 8 successful attacks
  
![Diagram](https://github.com/aele1401/WebDav_Pentest/blob/main/Images/Bruteforce.PNG)
![Diagram](https://github.com/aele1401/WebDav_Pentest/blob/main/Images/Uncovering_Bruteforce.PNG)

### Analysis: Finding the WebDAV Connection
- 4 requests for the WebDAV folder
- Most requests for `shell.php` and `passwd.dav` files
  
![Diagram](https://github.com/aele1401/WebDav_Pentest/blob/main/Images/HTTP_Transactions.PNG)
![Diagram](https://github.com/aele1401/WebDav_Pentest/blob/main/Images/webdav_packetbeat.PNG)

## Hardening: Proposed Alarms & Mitigation Strategies

### Mitigating Port Scans
- Implementing Alerts, Processes, and Tools:
    * Set alert for unusually high number of connection attempts (Per IP) with 5,000 connections per hour
    * Alerts for connection attempts to unused or closed ports
    * SYN scan detection
    * Stealth scan detection (XMAS, FIN, null, or decoy scans)
    * Alerts for multiple connection attempts across various subnets
    * Alerts for outbound traffic to known malicious IPs or ports
    * CPU Usage Alert to help detect malware
    * Web Application Firewall (inbound & outbound traffic with rules)
    * Properly configure and implement:
        - Firewalls
        - SIEM & SOAR
        - IDS & IPS
        - EDR & AV
    * Conduct threat hunting, research, security testing, OSINT, an incident response plan, and additional tools and methods to create custom detections and alerts for environment.
        - Tailor alerts to environment
        - Less detections that are highly effective
- Firewall Implementation:
    * Properly configure firewalls to:
        - Block Unused Ports: Ensure that only the required ports are open. All other ports should be blocked or filtered by a firewall.
        - Stealth Mode: Some firewalls can be configured in "stealth mode," where they do not respond to closed port requests, making it harder for attackers to distinguish between open and closed ports.
        - Rate Limiting: Configure rate-limiting to throttle the number of connection attempts from a single IP in a short period, reducing the effectiveness of a port scan.
        - Default Deny Policy: Adopt a "deny by default, allow by exception" firewall policy to limit exposure.
- Implement an IDS/IPS:
    * Detect and Block Scans: IDS/IPS can detect common scanning behaviors (SYN, FIN, Xmas, Null scans) and block the scanning IP automatically or alert security teams to take action.
    * Signature-based Detection: Use signature-based detection in IDS/IPS systems to catch known scanning tools like Nmap or masscan.
    * Behavioral Analysis: Modern IDS/IPS systems also support anomaly detection, which can flag abnormal connection attempts.
- Network Segmentation:
    * Isolate Sensitive Systems: Segregate sensitive systems (e.g., databases, internal services) from the public-facing infrastructure by using VLANs or network segmentation.
    * Limit Lateral Movement: Even if an attacker gains access to one network segment, segmentation limits their ability to scan other segments and discover further targets.
- Use Port Knocking or Single Packet Authorization (SPA):
    * Port Knocking: This technique keeps ports closed until the correct "knock" sequence is performed, effectively hiding services from port scanners. Once the correct sequence of packets is sent, the firewall opens the port temporarily.
    * SPA: A more secure alternative to port knocking, where the firewall only opens the port if a specific, encrypted packet is received.
- Implement Network Address Translation (NAT):
    * Hide Internal Network Structure: By using NAT, internal IP addresses are hidden from external sources. This reduces the visibility of internal network topology to attackers conducting port scans.
- Deny Requests from Suspicious IPs:
    * Blacklist: Automatically or manually block IP addresses that exhibit port scanning behavior. Set a rule on the firewall or IDS/IPS to block IPs that trigger scan detection alerts.
    * Geofencing: If applicable, restrict traffic from regions where your organization does not conduct business, limiting the risk of scans from remote attackers.
- Monitor and Limit External Exposure:
    * Regular Network Audits: Perform regular scans of your own infrastructure to identify unnecessary open ports and services.
    * Minimize Open Ports: Only expose services that need to be accessed from external networks. For example, if SSH is not needed externally, restrict it to internal access or specific IPs.
- Honeypots:
    * Detect Scanners: Deploy honeypots that are designed to look like real services but are meant to attract and log unauthorized access attempts, such as port scans.
    * Divert and Study Attacks: Honeypots help collect data on the tactics attackers use, allowing you to respond to emerging threats more effectively.
### Mitigation: Finding the Request for the Hidden Directory
- Alerts:
    *  Set alerts for requests made to restricted directories
    * Set alerts for unauthorized access into restricted directories
    * No more than 8 attempts per hour
- System Hardening:
    * Encrypt files
    * Restrict public access
    * Limit sharing of confidential files
### Mitigation: Preventing Brute Force Attacks
- Alerts:
    * Alerts for 401 errors
    * 10 errors per hour
- System Hardening:
    * Password Policies & Account Lockouts
    * Blacklist IP Addresses
    * Limit failed login attempts
    * Review account policies
### Mitigation: Detecting the WebDAV Connection
- Alerts & Implementations:
    * Create a list of WebDAV users (ACLs)
    * Whitelist IP addresses (only from trusted sources)
    * Blacklist IP addresses outside of set range
    * Set alerts for requests made from devices not on list
- System Hardening:
    * Effective password policies
    * Whitelist IPs
    * Prevent unauthorized access
### Mitigation: Identifying Reverse Shell Uploads
- Alerts:
    * Set alerts for uploads into restricted directories
    * Alerts on ports 4444, 443, and 80
- System Hardening:
    * Filter ports
    * Filter IP addresses
    * Set permissions and access controls
    * Baseline configurations
    * Implement proper security controls
    * Require password with sudo commands










