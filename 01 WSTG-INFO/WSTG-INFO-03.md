# WSTG-INFO-03: Review Webserver Metafiles for Information Leakage

## Objective
To analyze the existence and contents of web server metafiles that may unintentionally disclose sensitive information about the application, server, or organization.

## Key Steps

### 1. Identify Common Metafiles
Search for the presence of common metafiles that may reveal sensitive information.
- Example files to check:
  - `robots.txt`
  - `sitemap.xml`
  - `.htaccess`
  - `.gitignore`
  - `.env`
  - `web.config`
  - `.git`
  - `composer.json`, `package.json`

### 2. Analyze `robots.txt`
Check for directories or files disallowed by `robots.txt`.
- Example URL:
  ```
  http://targetdomain.com/robots.txt
  ```
- Look for disallowed entries that might indicate sensitive directories:
  ```
  Disallow: /admin
  Disallow: /backup
  ```

### 3. Review `sitemap.xml`
Examine the `sitemap.xml` file for hidden or non-public endpoints.
- Example URL:
  ```
  http://targetdomain.com/sitemap.xml
  ```
- Look for:
  - Directories with sensitive data
  - API endpoints

### 4. Check for Configuration Files
Search for exposed configuration files that may contain sensitive details.
- Example files:
  - `.htaccess`
  - `web.config`
  - `.env`
- Use automated tools or manual search to locate these files.

### 5. Analyze Version Control and Backup Files
Identify exposed version control files or backups:
- Files to search for:
  - `.git/`
  - `.svn/`
  - `backup.zip`
  - `database.sql`
- Tools:
  - `gobuster`
  - `dirb`

### 6. Detect Hidden Files and Directories
Enumerate hidden files and directories that may be unintentionally exposed.
- Tools:
  - `dirb`:
    ```bash
    dirb http://targetdomain.com
    ```
  - `ffuf`:
    ```bash
    ffuf -u http://targetdomain.com/FUZZ -w wordlist.txt
    ```

### 7. Document Findings
Maintain detailed notes on identified metafiles:
- File paths
- Sensitive information disclosed
- Potential risks and impact

## Tools and Resources
- **Command Line**:
  - `curl`, `wget`
- **Tools**:
  - gobuster
  - dirb
  - ffuf
- **Online Tools**:
  - [robots.txt Checker](https://www.robotschecker.com/)
  - [XML Sitemap Validator](https://www.xml-sitemaps.com/validate-xml-sitemap.html)

## Mitigation Recommendations
- Restrict access to sensitive metafiles using proper permissions.
- Avoid storing sensitive information in publicly accessible locations.
- Regularly audit webserver directories for unintended exposures.

---

**Next Steps:**
Proceed to [WSTG-INFO-04: Enumerate Applications on Webserver](./WSTG_INFO_04.md).
