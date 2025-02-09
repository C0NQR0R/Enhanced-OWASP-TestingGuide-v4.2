# WSTG-CONF-03: Test File Extensions Handling for Sensitive Information

## Objective
Ensure that the application platform securely handles file extensions to prevent unintended exposure of sensitive information.

## Checklist

### 1. Test for Sensitive File Exposure
- Attempt to access sensitive files such as:
  - `config.php`
  - `.env`
  - `web.config`
  - `.htaccess`
- Identify whether these files are accessible via the web browser.

### 2. Verify Handling of Backup Files
- Check if backup or temporary files are publicly accessible:
  - `.bak`
  - `.swp`
  - `.old`
  - `~` (tilde) files.
- Test common backup naming conventions (e.g., `index.php.bak`).

### 3. Analyze Error Messages for Leaks
- Review server error messages for clues about sensitive files, paths, or extensions.

### 4. Attempt Path Traversal
- Test for improper handling of file paths using patterns like:
  - `../../filename.ext`
  - `%2e%2e%2f`
  - `....//....//`
  - `..%252f..%252f`

### 5. Assess File Upload Restrictions
- Ensure that:
  - Uploaded files with dangerous extensions (e.g., `.exe`, `.php`) are restricted.
  - MIME type validation is enforced.

### 6. Check File Parsing Vulnerabilities
- Validate that untrusted extensions (e.g., `.txt`) are not treated as executable or scriptable files.

### 7. Inspect Directory Indexing
- Confirm directory indexing is disabled to prevent enumeration of file extensions.

## Tools
- **Burp Suite**: For crafting and testing malicious file paths and extensions.
- **Dirb/Gobuster**: For brute-forcing file and directory names.
- **Nikto**: For automated file and directory vulnerability scanning.

---

Let me know if you'd like any adjustments or if you're ready to move to the next file!
