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




