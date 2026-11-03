# TryHackMe Report: Conti, Network Security Essentials and Splunk Basics

This report covers three TryHackMe rooms. All of them are about investigating an attack from logs.

- **Conti:** a ransomware attack on an Exchange server, investigated in Splunk.
- **Network Security Essentials:** a perimeter breach at Initech Corp, investigated with command line tools.
- **Splunk Basics:** an attack on a web server, from first probe to ransomware, investigated in Splunk.

# Part 1: Conti

## Scenario

Employees could not log in to Outlook and the Exchange admin could not open the Exchange Admin Center. Readme files had also appeared on the server, and one of them was a Conti ransom note. I used the Splunk instance on the lab machine and accessed it from the AttackBox.

## Finding the ransomware

I searched Sysmon event ID 11 (file creation) for files with "readme" in the name. There were 18 events, and all of them came from one process.

- **Ransomware location:** `C:\Users\Administrator\Documents\cmd.exe`
- **Sysmon event ID:** 11
- **File saved to multiple folders:** `readme.txt`

The name `cmd.exe` is meant to look normal, but the real one runs from System32, not from a user's Documents folder.

**Evidence: Ransomware location**
![Ransomware location](screenshots/conti_01_ransomware_location.jpg)

## Getting the hash

I searched Sysmon event ID 1 (process creation) for that path and pulled the hash out of the event.

- **MD5:** `290c7dfb01e50cea9e19da81a781af2c`

**Evidence: MD5 hash**
![MD5 hash](screenshots/conti_02_md5_hash.jpg)

## New user account

I searched process creation events for command lines containing `/add`. The attacker created a user and then added it to two local groups.

- **Command:** `net user /add securityninja hardToHack123$`
- **Groups added to:** administrators and Remote Desktop Users

**Evidence: New user**
![New user](screenshots/conti_03_new_user.jpg)

## Process injection

Sysmon event ID 8 records one process creating a thread in another. There were only 2 events: PowerShell injected into `unsecapp.exe`, which then injected into `lsass.exe`.

- **Migration target:** `C:\Windows\System32\wbem\unsecapp.exe`
- **Process used to get hashes:** `C:\Windows\System32\lsass.exe`

**Evidence: Process injection**
![Process injection](screenshots/conti_04_process_injection.jpg)

## Web shell

I searched process creation events for command lines containing `.aspx`, then checked the IIS logs. The file has a random name and sits in the OWA auth folder. The IIS logs show 4 POST requests to it.

- **Web shell:** `i3gfPctK1c2x.aspx`
- **Command line:** `attrib.exe  -r \\\\win-aoqkg2as2q7.bellybear.local\C$\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\i3gfPctK1c2x.aspx`

**Evidence: Web shell command**
![Web shell command](screenshots/conti_05_webshell_command.jpg)

**Evidence: IIS logs**
![IIS logs](screenshots/conti_06_iis_webshell.jpg)

## CVEs

The IIS logs have 31 events for `autodiscover.json`, and some of the requests carry `PowerShell` and `X-Rps-CAT` in the query. This looks like ProxyShell, which public reports link to Conti.

- **Answer the room accepted:** CVE-2018-13374, CVE-2018-13379, CVE-2020-0796
- **Answer the room rejected:** CVE-2021-31207, CVE-2021-34473, CVE-2021-34523 (the ProxyShell CVEs)

The accepted answer did not come from the logs. It was chosen to fit the room's answer format and what is known about Conti. The logs point more towards ProxyShell.

**Evidence: Autodiscover requests**
![Autodiscover requests](screenshots/conti_07_proxyshell_requests.jpg)

## Room result

All questions were answered and the room was completed for 300 points.

**Evidence: Conti room completed**
![Conti room completed](screenshots/conti_08_room_completed.jpg)

# Part 2: Network Security Essentials

## Scenario

Initech Corp had deployed a new firewall and IDS, but the SOC team did not have time to look into some abnormal traffic. The task was to review one month of perimeter logs and find out if the attacker got in.

The logs are in `Perimeter_logs/challenge` on the lab machine: `firewall.log`, `ids_alerts.log` and `vpn_auth.log`.

This room was already at 100% when I opened it, with the answers saved. I went through the logs again to check those answers.

## Reconnaissance

I counted blocked firewall requests by source IP. 203.0.113.45 did the most reconnaissance with 279, ahead of 203.0.113.10 (46) and 10.8.0.23 (26). Its blocked requests mostly went to 10.0.0.50 (131) and 10.0.0.20 (124). The room's accepted answer for the scanned host is 10.0.0.20, even though 10.0.0.50 has slightly more.

**Evidence: Firewall reconnaissance**
![Firewall reconnaissance](screenshots/nse_01_firewall_recon.jpg)

## VPN brute force

The same IP failed 118 VPN logins against `svc_backup`. It got in on 2025-09-03 at 02:19:40 and was assigned 10.8.0.23.

## Lateral movement

The IDS logs show SMB lateral movement alerts from 10.8.0.23 on port 445, against 10.0.0.60 (13), 10.0.0.20 (11) and 10.0.0.51 (8).

## C2 and exfiltration

- **C2 beaconing:** 10.0.0.60 to 198.51.100.77 on port 4444, 80 alerts
- **Exfiltration:** 10.0.0.51 to 198.51.100.77, 60 large HTTP POST alerts (32 on port 80, 28 on port 8080)

**Evidence: Log analysis**
![Log analysis](screenshots/nse_02_log_analysis.jpg)

## Room result

**Evidence: Task 7 answers**
![Task 7 answers](screenshots/nse_03_task7_answers.jpg)

**Evidence: Room completed**
![Room completed](screenshots/nse_04_room_completed.jpg)

# Part 3: Splunk Basics - Did you SIEM?

## Scenario

In this room I used Splunk to investigate an attack on a web server, find the attacker and follow the steps of the attack.

## Exploring the logs

I started by showing all the logs, with the time range set to All time. This returned 18,744 events.

**Evidence: index=main search**
![index=main search](screenshots/splunk_01_index_main.png)

The `sourcetype` field showed two data sources:

- `web_traffic`: 17,172 events about connections to the web server
- `firewall_logs`: 1,572 events showing traffic that was allowed or blocked

**Evidence: Source types**
![Source types](screenshots/splunk_02_sourcetypes.png)

Next I searched only the web traffic and opened one event to see its fields.
Fields like `client_ip`, `path`, `status` and `user_agent` were extracted correctly.

**Evidence: Web traffic event**
![Web traffic event](screenshots/splunk_03_web_traffic_event.png)

## Finding the peak day

To see the traffic per day, I charted the event count with a span of one day.

**Evidence: Timechart**
![Timechart](screenshots/splunk_04_timechart.png)

The graph made it easy to see a big spike from 10 to 14 October.

**Evidence: Timechart graph**
![Timechart graph](screenshots/splunk_05_timechart_graph.png)

I then sorted the results so the busiest day came first. The peak day was 2025-10-12.

**Evidence: Peak day**
![Peak day](screenshots/splunk_06_peak_day.png)

## Finding the attacker

I looked at three fields to find anything suspicious.
The `user_agent` field had normal browsers, but also tools like Wget, zgrab, curl, sqlmap and Havij.
It showed 993 Havij events.

**Evidence: user_agent field**
![user_agent field](screenshots/splunk_07_user_agent.png)

In the `client_ip` field, one IP stood out with 7,876 events, which is about 46% of the web traffic.

**Evidence: client_ip field**
![client_ip field](screenshots/splunk_08_client_ip.png)

The `path` field showed attack strings such as `SLEEP(5)` and `../../etc/passwd`.
The path traversal request appeared 658 times.

**Evidence: path field**
![path field](screenshots/splunk_09_path.png)

To confirm the attacker, I filtered out the normal browsers. All 7,876 remaining events came from one IP, 198.51.100.55.

**Evidence: Browsers filtered out**
![Browsers filtered out](screenshots/splunk_10_filter_browsers.png)

Counting the events by IP gave the same result.

**Evidence: Top IP**
![Top IP](screenshots/splunk_11_top_ip.png)

## Tracing the attack

### Reconnaissance

The attacker first looked for exposed files like `/.env`, `/phpinfo.php` and `/.git/config`.
This search returned 1,444 events.

**Evidence: Recon**
![Recon](screenshots/splunk_12_recon.png)

### Enumeration

Next the attacker tested for path traversal and open redirect, with 1,291 events in total.

**Evidence: Traversal search**
![Traversal search](screenshots/splunk_13_traversal_search.png)

Counting by path split these into `/?redirect=http://evil.site` and `/download?file=../../etc/passwd`.

**Evidence: Traversal count**
![Traversal count](screenshots/splunk_14_traversal_count.png)

### SQL injection

The attacker then used sqlmap and Havij, with payloads like `SLEEP(5)`, across 1,960 events.

**Evidence: SQL injection**
![SQL injection](screenshots/splunk_15_sql_injection.png)

### Exfiltration

There were 347 events for large files, such as `/logs.tar.gz`, using tools like curl and zgrab.

**Evidence: Exfiltration**
![Exfiltration](screenshots/splunk_16_exfiltration.png)

### Webshell and ransomware

Finally, the attacker used `shell.php` to run commands, including `./bunnylock.bin`, across 1,092 events.

**Evidence: Webshell**
![Webshell](screenshots/splunk_17_webshell_rce.png)

## C2 traffic

I moved to the firewall logs to check traffic from the compromised server, 10.10.1.5, to the attacker. There were 285 allowed connections on port 8080, all marked `C2_CONTACT`.

**Evidence: C2 connections**
![C2 connections](screenshots/splunk_18_c2_firewall.png)

I then added up the bytes sent over this connection. The total was 126167 bytes.

**Evidence: Bytes transferred**
![Bytes transferred](screenshots/splunk_19_bytes_transferred.png)

## Room result

- Attacker IP: 198.51.100.55
- Peak traffic day: 2025-10-12
- Havij user_agent events: 993
- Path traversal attempts: 658
- Bytes transferred to the C2 server: 126167

**Evidence: Answers**
![Answers](screenshots/splunk_20_answers.png)

# Conclusion

All three attacks could be followed step by step from the logs. In Conti, Sysmon event IDs 1, 8 and 11 showed the ransomware, the injection and the new user, while IIS logs showed the web shell. In Network Security Essentials, linking the attacker's IP across all three logs showed the path from scanning to VPN access, lateral movement, C2 and exfiltration.

In Splunk Basics, filtering and correlating logs narrowed the traffic down to one IP, followed it from first probe to ransomware, and the firewall logs confirmed the server was talking to the attacker's C2.