# VulnHub Kioptrix Level 1 Walkthrough

Note: I'm using Kali Linux and Kioptrix VM both on VMWare Player. Both are on NAT.

## Information Gathering

- `ifconfig` or `ip a` to get the IP address on Kali Linux.
- IP = 192.168.92.129
- `sudo netdiscover -r 192.168.92.0/24`
- Let `netdiscover` run for a while if it doesn't show any IP addresses instantly.

- **NetDiscover Output:**

  ```
  192.168.92.1    MAC_ID_XXXXX      2     120  VMware, Inc.
  192.168.92.2    MAC_ID_XXXXX      4     240  VMware, Inc.
  192.168.92.128  MAC_ID_XXXXX      3     180  VMware, Inc.
  192.168.92.254  MAC_ID_XXXXX      3     180  VMware, Inc.
  ```

- Can't say for sure but `192.168.92.128` looks like the Kioptrix machine so we will try with that IP first.

## Recon - Enumeration and Scanning

### nmap

- `nmap -T4 -p- -A 192.168.92.128`

- **Nmap Output:**

  ```
  PORT      STATE SERVICE     VERSION
  22/tcp    open  ssh         OpenSSH 2.9p2 (protocol 1.99)
  | ssh-hostkey:
  |   1024 b8:74:6c:db:fd:8b:e6:66:e9:2a:2b:df:5e:6f:64:86 (RSA1)
  |   1024 8f:8e:5b:81:ed:21:ab:c1:80:e1:57:a3:3c:85:c4:71 (DSA)
  |_  1024 ed:4e:a9:4a:06:14:ff:15:14:ce:da:3a:80:db:e2:81 (RSA)
  |_sshv1: Server supports SSHv1
  80/tcp    open  http        Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)
  | http-methods:
  |_  Potentially risky methods: TRACE
  |_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
  |_http-title: Test Page for the Apache Web Server on Red Hat Linux
  111/tcp   open  rpcbind     2 (RPC #100000)
  | rpcinfo:
  |   program version    port/proto  service
  |   100000  2            111/tcp   rpcbind
  |   100000  2            111/udp   rpcbind
  |   100024  1          32768/tcp   status
  |_  100024  1          32768/udp   status
  139/tcp   open  netbios-ssn Samba smbd (workgroup: MYGROUP)
  443/tcp   open  ssl/https   Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
  |_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
  |_http-title: 400 Bad Request
  | ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
  | Not valid before: 2009-09-26T09:32:06
  |_Not valid after:  2010-09-26T09:32:06
  |_ssl-date: 2021-02-01T21:06:40+00:00; +1h01m57s from scanner time.
  | sslv2:
  |   SSLv2 supported
  |   ciphers:
  |     SSL2_RC2_128_CBC_WITH_MD5
  |     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
  |     SSL2_RC4_128_EXPORT40_WITH_MD5
  |     SSL2_DES_64_CBC_WITH_MD5
  |     SSL2_RC4_64_WITH_MD5
  |     SSL2_RC4_128_WITH_MD5
  |_    SSL2_DES_192_EDE3_CBC_WITH_MD5
  32768/tcp open  status      1 (RPC #100024)

  Host script results:
  |\_clock-skew: 1h01m56s
  |\_nbstat: NetBIOS name: KIOPTRIX, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
  |\_smb2-time: Protocol negotiation failed (SMB2)
  ```

- Ports 80, 443 (web) and 139 (SMB) should be worth looking into first.
- Lets also run `nikto` to see what else we find automatically.

### nikto

- `nikto -h http://192.168.92.128`

- **Nikto Output:**

  ```
  - Nikto v2.1.6
  - Target IP: 192.168.92.128
  - Target Hostname: 192.168.92.128
  - Target Port: 80
  - Start Time: 2021-02-01 15:34:36 (GMT-5)

  ---

  - Server: Apache/1.3.20 (Unix) (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
  - Server may leak inodes via ETags, header found with file /, inode: 34821, size: 2890, mtime: Wed Sep 5 23:12:46 2001
  - The anti-clickjacking X-Frame-Options header is not present.
  - The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
  - The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
  - OSVDB-27487: Apache is vulnerable to XSS via the Expect header
  - mod_ssl/2.8.4 appears to be outdated (current is at least 2.8.31) (may depend on server version)
  - Apache/1.3.20 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
  - OpenSSL/0.9.6b appears to be outdated (current is at least 1.1.1). OpenSSL 1.0.0o and 0.9.8zc are also current.
  - Allowed HTTP Methods: GET, HEAD, OPTIONS, TRACE
  - OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
  - OSVDB-838: Apache/1.3.20 - Apache 1.x up 1.2.34 are vulnerable to a remote DoS and possible code execution. CAN-2002-0392.
  - OSVDB-4552: Apache/1.3.20 - Apache 1.3 below 1.3.27 are vulnerable to a local buffer overflow which allows attackers to kill any process on the system. CAN-2002-0839.
  - OSVDB-2733: Apache/1.3.20 - Apache 1.3 below 1.3.29 are vulnerable to overflows in mod_rewrite and mod_cgi. CAN-2003-0542.
  - mod_ssl/2.8.4 - mod_ssl 2.8.7 and lower are vulnerable to a remote buffer overflow which may allow a remote shell. http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0082, OSVDB-756.
  - ///etc/hosts: The server install allows reading of any system file by adding an extra '/' to the URL.
  - OSVDB-682: /usage/: Webalizer may be installed. Versions lower than 2.01-09 vulnerable to Cross Site Scripting (XSS).
  - OSVDB-3268: /manual/: Directory indexing found.
  - OSVDB-3092: /manual/: Web server manual found.
  - OSVDB-3268: /icons/: Directory indexing found.
  - OSVDB-3233: /icons/README: Apache default file found.
  - OSVDB-3092: /test.php: This might be interesting...
  - /wp-content/themes/twentyeleven/images/headers/server.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
  - /wordpresswp-content/themes/twentyeleven/images/headers/server.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
  - /wp-includes/Requests/Utility/content-post.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
  - /wordpresswp-includes/Requests/Utility/content-post.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
  - /wp-includes/js/tinymce/themes/modern/Meuhy.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
  - /wordpresswp-includes/js/tinymce/themes/modern/Meuhy.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
  - /assets/mobirise/css/meta.php?filesrc=: A PHP backdoor file manager was found.
  - /login.cgi?cli=aa%20aa%27cat%20/etc/hosts: Some D-Link router remote command execution.
  - /shell?cat+/etc/hosts: A backdoor was identified.
  - 8724 requests: 0 error(s) and 30 item(s) reported on remote host

  ```

- Interesting `nikto` findings: `mod_ssl/2.8.4 - mod_ssl 2.8.7 and lower are vulnerable to a remote buffer overflow which may allow a remote shell. http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0082, OSVDB-756.` because it might give us a remote shell access.

### gobuster

- Lets run gobuster and see what directories it lists.
- `sudo gobuster dir -u http://192.168.92.128 -t 32 -w /usr/share/wordlists/dirb/common.txt -x .php,.html,.asp,.aspx,.py`

- Gobuster Output:

  ```
  =============================
  /.htaccess (Status: 403)
  /.htaccess.asp (Status: 403)
  /.htaccess.aspx (Status: 403)
  /.htaccess.py (Status: 403)
  /.htaccess.php (Status: 403)
  /.htaccess.html (Status: 403)
  /.hta (Status: 403)
  /.hta.php (Status: 403)
  /.hta.html (Status: 403)
  /.hta.asp (Status: 403)
  /.hta.aspx (Status: 403)
  /.hta.py (Status: 403)
  /.htpasswd (Status: 403)
  /.htpasswd.php (Status: 403)
  /.htpasswd.html (Status: 403)
  /.htpasswd.asp (Status: 403)
  /.htpasswd.aspx (Status: 403)
  /.htpasswd.py (Status: 403)
  /~operator (Status: 403)
  /~root (Status: 403)
  /cgi-bin/ (Status: 403)
  /cgi-bin/.html (Status: 403)
  /index.html (Status: 200)
  /index.html (Status: 200)
  /manual (Status: 301)
  /mrtg (Status: 301)
  /test.php (Status: 200)
  /usage (Status: 301)
  =============================

  ```

### MetaSploit

- Lets check port 139 for SMB now. We will use MetaSploit.
- `msfconsole` => `search smb` => `use {number for auxiliary/scanner/smb/smb_version}`
- `show options` => `set RHOSTS 192.168.92.128` => `run`
- MetaSploit Output:

  ```
  [*] 192.168.92.128:139    - SMB Detected (versions:) (preferred dialect:) (signatures:optional)
  [*] 192.168.92.128:139    -   Host could not be identified: Unix (Samba 2.2.1a)
  [*] 192.168.92.128:       - Scanned 1 of 1 hosts (100% complete)
  [*] Auxiliary module execution completed

  ```

- Version information: **Samba 2.2.1a** is very specific and will help us a lot in exploitation.

### smbclient

- Lets try **SMBClient**.
- `smbclient -L \\192.168.92.128`
- OR `smbclient -L \\\\192.168.92.128\\` (with character escaping)
- Note: Question: My enum4linux and/or smbclient are not working. I am receiving "Protocol negotiation failed: NT_STATUS_IO_TIMEOUT". How do I resolve?
- Resolution: On Kali, edit `/etc/samba/smb.conf` to add the following under `global`:

```
  client min protocol = CORE

  client max protocol = SMB3
```

- `sudo nano /etc/samba/smb.conf` and make the necessary changes.
- `smbclient -L \\\\192.168.92.128\\` (with character escaping)
- Keep password empty and press enter to try anonymous login.
- SMBClient Output:

  ```
  Server does not support EXTENDED_SECURITY  but 'client use spnego = yes' and 'client ntlmv2 auth = yes' is set
  Anonymous login successful
  Enter WORKGROUP\kali's password:

    Sharename       Type      Comment
    ---------       ----      -------
    IPC$            IPC       IPC Service (Samba Server)
    ADMIN$          IPC       IPC Service (Samba Server)
  Reconnecting with SMB1 for workgroup listing.
  Server does not support EXTENDED_SECURITY  but 'client use spnego = yes' and 'client ntlmv2 auth = yes' is set
  Anonymous login successful

    Server               Comment
    ---------            -------
    KIOPTRIX             Samba Server

    Workgroup            Master
    ---------            -------
    MYGROUP              KIOPTRIX

  ```

- Try `smbclient \\\\192.168.92.128\\ADMIN$` with empty password => fails!
- Try `smbclient \\\\192.168.92.128\\IPC$` with empty password => succeeds!
- Try `ls` to list files.
- ```
  smb: \> ls
  NT_STATUS_NETWORK_ACCESS_DENIED listing \*
  ```
- But we can't really use any commands or do anything so its kind of a dead end.

### ssh

- From earlier `nmap` scan, we know that **OpenSSH 2.9p2** is running on port 22. Lets do some SSH enumeration.
- `ssh 192.168.92.128`
- output: Unable to negotiate with 192.168.92.128 port 22: no matching key exchange method found. Their offer: diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1
- SSH errors and fixing SSH errors.
- Kioptrix is an old machine so this is happening. Although not common, this is sometimes seen. We need to use `-oKexAlgorithms` with one of the options they have provided.
- `ssh 192.168.92.128 -oKexAlgorithms=+diffie-hellman-group1-sha1`
- output: Unable to negotiate with 192.168.92.128 port 22: no matching cipher found. Their offer: aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,arcfour,aes192-cbc,aes256-cbc,rijndael128-cbc,rijndael192-cbc,rijndael256-cbc,rijndael-cbc@lysator.liu.se
- No matching cypher found so lets use `-c` flag for cypher and choose the first option from the output.
- `ssh 192.168.92.128 -oKexAlgorithms=+diffie-hellman-group1-sha1 -c aes128-cbc`
- It now asks for password but we don't have one. And sometimes a **banner** is exposed which might contain some information like SSH version, who configured the SSH connection (think username), etc which might give us more information to dig into. This is a dead end for now, but it is important to know how to resolve issues like these seen on older linux machines.
