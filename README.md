# TryHackMe Lab Report

Rooms covered: Conti, Network Security Essentials and Splunk Basics.

# Room 1: Conti

## 1. Aim

To investigate a Conti ransomware attack on an Exchange server using Splunk.

## 2. Objectives

- Find the ransomware file and its MD5 hash
- Find the user account the attacker created
- Trace the process injection used to get system hashes
- Find the web shell and the command that ran it
- Identify the vulnerabilities used in the attack

## 3. What I Understood

- Sysmon event IDs are useful for narrowing a search. ID 1 is process creation, ID 8 is a process creating a thread in another process and ID 11 is file creation.
- Malware can use a normal name to hide. The real `cmd.exe` runs from System32, not a user's Documents folder.
- Attackers inject into processes like `lsass.exe` because it holds credentials.
- A file with a random name in a web folder that receives POST requests is a strong sign of a web shell.
- A room's accepted answer and the log evidence do not always match, so both should be checked.

## 4. Summary

The ransomware was `C:\Users\Administrator\Documents\cmd.exe`, with MD5 `290c7dfb01e50cea9e19da81a781af2c`. It saved `readme.txt` to many folders (Sysmon event ID 11).

The attacker added a user with `net user /add securityninja hardToHack123$`. PowerShell injected into `C:\Windows\System32\wbem\unsecapp.exe`, which then injected into `C:\Windows\System32\lsass.exe` to get hashes.

The web shell was `i3gfPctK1c2x.aspx`, and the command line was `attrib.exe  -r \\\\win-aoqkg2as2q7.bellybear.local\C$\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\i3gfPctK1c2x.aspx`.

The room accepted CVE-2018-13374, CVE-2018-13379 and CVE-2020-0796. This answer did not come from the logs. It was chosen to fit the room's answer format and what is known about Conti. The IIS logs look more like ProxyShell, but the room rejected the ProxyShell CVEs (CVE-2021-31207, CVE-2021-34473, CVE-2021-34523).

## 5. Lab Screenshots

**Ransomware location.** Sysmon event ID 11 shows one process creating `readme.txt` in 18 events.

![Ransomware location](screenshots/conti_01_ransomware_location.jpg)

**MD5 hash.** The hash taken from the Sysmon process creation event.

![MD5 hash](screenshots/conti_02_md5_hash.jpg)

**New user.** The attacker creates `securityninja` and adds it to the administrators and Remote Desktop Users groups.

![New user](screenshots/conti_03_new_user.jpg)

**Process injection.** Sysmon event ID 8 shows the chain from PowerShell to `unsecapp.exe` to `lsass.exe`.

![Process injection](screenshots/conti_04_process_injection.jpg)

**Web shell command.** The `attrib.exe` command line that names the web shell.

![Web shell command](screenshots/conti_05_webshell_command.jpg)

**IIS logs.** Four POST requests to the web shell.

![IIS logs](screenshots/conti_06_iis_webshell.jpg)

**Autodiscover requests.** 31 `autodiscover.json` events, some with `PowerShell` and `X-Rps-CAT` in the query.

![Autodiscover requests](screenshots/conti_07_proxyshell_requests.jpg)

**Room completed.** All tasks done, with 300 points earned.

![Conti room completed](screenshots/conti_08_room_completed.jpg)

# Room 2: Network Security Essentials

## 1. Aim

To review one month of Initech Corp perimeter logs and find out if an attacker breached the network.

## 2. Objectives

- Find the external IP doing the most reconnaissance and its targets
- Find the VPN account that was attacked and the IP assigned to the attacker
- Check for lateral movement inside the network
- Find the C2 server and the host beaconing to it
- Find the host showing data exfiltration attempts

## 3. What I Understood

- Firewall, IDS and VPN logs each show only part of an attack. Following one IP across all three shows the full path.
- Many failed logins followed by a success is a clear sign of a brute force attack.
- Simple tools like `grep`, `cut`, `sort` and `uniq` are enough to find the main patterns in a log.
- Regular traffic to one external IP on an unusual port such as 4444 can point to C2.
- Large HTTP POST uploads to the same external IP can point to data exfiltration.

## 4. Summary

This room was already at 100% when I opened it, with the answers saved, so I went through the logs again to check them.

203.0.113.45 did the most reconnaissance, with 279 blocked requests. They mostly went to 10.0.0.50 (131) and 10.0.0.20 (124). The room's accepted answer for the scanned host is 10.0.0.20, even though 10.0.0.50 has slightly more.

The same IP failed 118 VPN logins against `svc_backup`, got in on 2025-09-03 at 02:19:40 and was assigned 10.8.0.23. From there, the IDS logged SMB lateral movement alerts on port 445 against 10.0.0.60 (13), 10.0.0.20 (11) and 10.0.0.51 (8).

10.0.0.60 beaconed to the C2 server 198.51.100.77 on port 4444 (80 alerts). 10.0.0.51 triggered 60 large HTTP POST alerts to the same IP (32 on port 80, 28 on port 8080).

## 5. Lab Screenshots

**Firewall reconnaissance.** Log files and blocked requests counted by source and target.

![Firewall reconnaissance](screenshots/nse_01_firewall_recon.jpg)

**Log analysis.** The VPN brute force, SMB alerts, C2 beaconing and exfiltration results.

![Log analysis](screenshots/nse_02_log_analysis.jpg)

**Task 7 answers.** The first five answers marked correct.

![Task 7 answers](screenshots/nse_03_task7_answers.jpg)

**Room completed.** All tasks ticked and the room at 100%.

![Room completed](screenshots/nse_04_room_completed.jpg)

# Room 3: Splunk Basics - Did you SIEM?

## 1. Aim

To use Splunk to investigate an attack on a web server, find the attacker and follow the steps of the attack.

## 2. Objectives

- Explore the logs and data sources in Splunk
- Find the peak traffic day
- Identify the attacker's IP from suspicious fields
- Trace the attack from reconnaissance to ransomware
- Confirm C2 traffic and count the bytes transferred

## 3. What I Understood

- Filtering and correlating logs in Splunk can trace a full attack.
- A `timechart` makes unusual traffic spikes easy to see.
- Fields like `user_agent`, `client_ip` and `path` quickly show attack tools and suspicious requests.
- Filtering out normal browsers can leave only the attacker's traffic.
- Web logs show what the attacker did, and firewall logs confirm the server's connection back to them.

## 4. Summary

The logs held 18,744 events: 17,172 in `web_traffic` and 1,572 in `firewall_logs`. Traffic spiked from 10 to 14 October, peaking on 2025-10-12.

The attacker was 198.51.100.55, with 7,876 events. The attack went through these stages:

- **Reconnaissance:** looking for files like `/.env` and `/.git/config` (1,444 events)
- **Enumeration:** path traversal and open redirect (1,291 events, including 658 path traversal attempts)
- **SQL injection:** sqlmap and Havij with payloads like `SLEEP(5)` (1,960 events, including 993 Havij)
- **Exfiltration:** large files like `/logs.tar.gz` (347 events)
- **Webshell and ransomware:** `shell.php` running `./bunnylock.bin` (1,092 events)

The firewall logs showed 285 allowed connections from the compromised server, 10.10.1.5, to the attacker on port 8080, all marked `C2_CONTACT`. A total of 126167 bytes were transferred.

## 5. Lab Screenshots

**index=main search.** All logs over All time, with 18,744 events.

![index=main search](screenshots/splunk_01_index_main.png)

**Source types.** The two data sources in the logs.

![Source types](screenshots/splunk_02_sourcetypes.png)

**Web traffic event.** One event with its extracted fields.

![Web traffic event](screenshots/splunk_03_web_traffic_event.png)

**Timechart.** Event count per day.

![Timechart](screenshots/splunk_04_timechart.png)

**Timechart graph.** The spike from 10 to 14 October.

![Timechart graph](screenshots/splunk_05_timechart_graph.png)

**Peak day.** Results sorted with 2025-10-12 first.

![Peak day](screenshots/splunk_06_peak_day.png)

**user_agent field.** Attack tools, including 993 Havij events.

![user_agent field](screenshots/splunk_07_user_agent.png)

**client_ip field.** One IP stands out with 7,876 events.

![client_ip field](screenshots/splunk_08_client_ip.png)

**path field.** Attack strings, including 658 path traversal requests.

![path field](screenshots/splunk_09_path.png)

**Browsers filtered out.** All 7,876 remaining events come from 198.51.100.55.

![Browsers filtered out](screenshots/splunk_10_filter_browsers.png)

**Top IP.** Counting events by IP gives the same result.

![Top IP](screenshots/splunk_11_top_ip.png)

**Reconnaissance.** Requests for exposed files.

![Recon](screenshots/splunk_12_recon.png)

**Traversal search.** Path traversal and open redirect requests.

![Traversal search](screenshots/splunk_13_traversal_search.png)

**Traversal count.** The events split by path.

![Traversal count](screenshots/splunk_14_traversal_count.png)

**SQL injection.** Requests from sqlmap and Havij.

![SQL injection](screenshots/splunk_15_sql_injection.png)

**Exfiltration.** Requests for large files.

![Exfiltration](screenshots/splunk_16_exfiltration.png)

**Webshell.** `shell.php` commands and `bunnylock.bin` requests.

![Webshell](screenshots/splunk_17_webshell_rce.png)

**C2 connections.** 285 allowed connections marked `C2_CONTACT`.

![C2 connections](screenshots/splunk_18_c2_firewall.png)

**Bytes transferred.** The total of 126167 bytes.

![Bytes transferred](screenshots/splunk_19_bytes_transferred.png)

**Answers.** All answers marked correct and the room at 100%.

![Answers](screenshots/splunk_20_answers.png)
