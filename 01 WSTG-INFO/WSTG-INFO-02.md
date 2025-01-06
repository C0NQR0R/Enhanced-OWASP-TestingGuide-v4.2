# WSTG-INFO-02: Fingerprint Web Server

## Objective
To identify the type, version, and underlying technologies of the web server to understand its vulnerabilities and configuration details.

## Key Steps

### 1. Identify HTTP Headers
Examine HTTP response headers to gather web server information.
- Use tools like `curl`, `wget`, or browser developer tools.
- Example command:
  ```bash
  curl -I http://targetdomain.com
  ```
- Headers to look for:
  - `Server`
  - `X-Powered-By`
  - `Via`

### 2. Check for Error Pages
Analyze custom error pages to determine web server details.
- Examples:
  - 404 Not Found
  - 500 Internal Server Error
- Tools:
  - Burp Suite
  - OWASP ZAP

### 3. Perform Banner Grabbing
Use tools to extract the server banner.
- Tools:
  - `nmap`
    ```bash
    nmap -sV -p80,443 targetdomain.com
    ```
  - `netcat`
    ```bash
    nc targetdomain.com 80
    GET / HTTP/1.1
    Host: targetdomain.com
    ```

### 4. Enumerate Open Ports
Identify open ports and associated services to understand the server environment.
- Use `nmap` or similar tools:
  ```bash
  nmap -sC -sV targetdomain.com
  ```

### 5. Detect Server-Side Technologies
Identify the technologies running on the web server.
- Look for CMSs, frameworks, or other technologies.
- Tools:
  - [WhatWeb](https://github.com/urbanadventurer/WhatWeb)
  - [Wappalyzer](https://www.wappalyzer.com/)

### 6. Test for Default Pages
Search for default or unused web pages that may reveal server details.
- Examples:
  - `/server-status`
  - `/server-info`
  - `/default.asp`, `/index.asp`
  - `/index.html`, `/default.html`
  - `/index.php.swp`, `/config.php~`

### 7. Analyze SSL/TLS Configuration
Check the SSL/TLS certificates for additional server information.
- Tools:
  - [SSL Labs](https://www.ssllabs.com/ssltest/)
  - `openssl`:
    ```bash
    openssl s_client -connect targetdomain.com:443
    ```

### 8. Document Findings
Maintain detailed notes on identified server details:
- Server type and version
- Associated frameworks or technologies
- Any misconfigurations or exposed information

## Tools and Resources
- **Command Line**:
  - `curl`, `wget`, `netcat`
  - `nmap`
- **Tools**:
  - WhatWeb
  - Wappalyzer
  - SSL Labs
- **Browser Extensions**:
  - BuiltWith
  - Wappalyzer

## Mitigation Recommendations
- Suppress or remove server version banners in HTTP headers.
- Implement custom error pages to avoid revealing server details.
- Regularly update and patch the web server and associated technologies.

---

**Next Steps:**
Proceed to [WSTG-INFO-03: Review Webserver Metafiles for Information Leakage](./WSTG_INFO_03.md).
