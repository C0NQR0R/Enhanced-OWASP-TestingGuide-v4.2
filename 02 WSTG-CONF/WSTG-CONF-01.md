# WSTG-CONF-01: Test Network Infrastructure Configuration

## Objective
To assess the network infrastructure configuration supporting the application and identify any misconfigurations or security gaps that could be exploited.

## Key Steps

### 1. Enumerate Open Ports and Services
- Use tools like `nmap` to scan for open ports and services:
  ```bash
  nmap -sV -p- targetdomain.com
  ```
- Identify services running on open ports (e.g., SSH, HTTP, SMTP).

### 2. Check for Firewalls and Intrusion Detection Systems
- Use tools to detect firewalls or intrusion detection systems (IDS):
  - [Firewalk](https://github.com/packetfactory/Firewalk)
  - `nmap` with firewall detection options:
    ```bash
    nmap -sA targetdomain.com
    ```

### 3. Test for Default or Weak Credentials
- Attempt to log in to accessible services using default or weak credentials.
    - try default credentials:
      - `(test:test)`, `(admin:admin)`
      - `(admin:password)`, `(kali:kali)`
      - `(admin:1234)`, `(admin:default)`
      - `(root:root)`, `(root:toor)`
      - `(admin:kali)`, `(kali:root)`
      - `(admin:123456789)`, `(administrator:password)`

- Use tools like Hydra or Medusa for brute force attempts (in a legal and controlled environment).

### 4. Review DNS Configuration
- Perform DNS enumeration using tools like `dnsenum` or `dig`:
  ```bash
  dig targetdomain.com any
  ```
- Check for:
  - Misconfigured DNS records (e.g., wildcard entries).
  - Leaked subdomains.

### 5. Check for Publicly Exposed Services
- Look for services that should not be exposed publicly (e.g., databases, admin panels).
- Websites:
  - [Shodan.io](https://www.shodan.io/)
  - [Censys.io](https://search.censys.io/)

### 6. Review Network Segmentation
- Verify that sensitive systems are isolated from public-facing networks.
- Check for improperly segmented networks using traceroute or similar tools.

### 7. Document Findings
Maintain a detailed log of identified issues:
- Open ports and services.
- Misconfigured or exposed systems.
- Recommendations for mitigation.

## Tools and Resources
- **Network Scanning**:
  - Nmap
  - Masscan
- **Brute Force**:
  - Hydra
  - Medusa
- **DNS Enumeration**:
  - Dnsenum
  - Dig
- **Explore Services**
  - Shodan
  - Censys

## Mitigation Recommendations
- Close unused ports and disable unnecessary services.
- Use strong credentials and enforce password policies.
- Implement firewalls and properly configure access control lists (ACLs).
- Regularly review and update DNS records.

---

**Next Steps:**
Proceed to [WSTG-CONF-02: Test Application Platform Configuration](./WSTG_CONF_02.md).
