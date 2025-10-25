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
  2cb2906a64c34654b0f0cb2271a6712d
```
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
  - sgpt --chat nikto --shell "launch nikto to execute a scan against the url www.certifiedhacker.com to identify potential vulnerabilities."
  - sgpt --chat nikto --shell "Scan the URL https://www.certifiedhacker.com to identify potential vulnerabilities with nikto"
  - sgpt --chat vuln --shell "perform a vulnerability scan on target url http://www.moviescope.com with nmap"
  - sgpt --chat vuln --shell "perform a vulnerability scan on target url http://testphp.vulnweb.com with skipfish"
</details>     

