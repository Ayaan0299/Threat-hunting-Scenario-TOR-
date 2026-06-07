# [![Typing SVG](https://readme-typing-svg.demolab.com?font=Fira+Code&weight=800&size=28&duration=1500&pause=1000&color=F753F3&width=1000&lines=THREAT+HUNT+REPORT+%7C+UNAUTHORISED+TOR+USAGE;MICROSOFT+DEFENDER+%7C+KQL+DETECTION;DEVICE%3A+AYAAN-VM-SOC)](https://git.io/typing-svg)

<p align="center">
  <img src="https://img.shields.io/badge/Azure-Cloud%20Security-0078D4?style=for-the-badge&logo=microsoftazure">
  <img src="https://img.shields.io/badge/Microsoft-Defender-0078D4?style=for-the-badge&logo=microsoft">
  <img src="https://img.shields.io/badge/KQL-Threat%20Hunting-orange?style=for-the-badge">
  <img src="https://img.shields.io/badge/Status-Confirmed-red?style=for-the-badge">
</p>

<p align="center">
  <img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo"/>
</p>

# Threat Hunt Report: Unauthorised TOR Usage


> **Note:** This is a simulated threat hunting scenario. `ayaan-vm-soc` is the lab VM used to replicate a corporate workstation, and `ayaanvm` represents the employee account. All events, queries, and findings reflect real activity performed within the lab environment.

---

## Platforms and Tools Used

- Windows 11 Virtual Machine (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- TOR Browser

---

## Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls, following unusual encrypted traffic patterns and connections to known TOR entry nodes appearing in recent network logs. There have also been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyse the related activity to mitigate potential risks. If use is confirmed, notify management.

---

## High-Level TOR IoC Discovery Plan

1. Check `DeviceFileEvents` for any `tor(.exe)` or `firefox(.exe)` file events
2. Check `DeviceProcessEvents` for any signs of installation or usage
3. Check `DeviceNetworkEvents` for any signs of outgoing connections over known TOR ports

---

## Steps Taken

### 1. Searched `DeviceFileEvents` for TOR-Related File Activity

Searched for any file events containing the string "tor" on the device. Results showed that the user `ayaanvm` (employee) downloaded a TOR installer to their Downloads folder. File creation events tied to the installer running with the `/s` (silent) flag were observed at `2026-06-06T16:21:35Z` and `2026-06-06T16:21:47Z`, confirming a background installation with no visible prompts. The same query also returned a file named `tor-shopping-list.txt` created in the Documents folder at `2026-06-06T16:37:29Z`, along with a corresponding `.lnk` shortcut in AppData — indicating the employee was documenting activity during their TOR session.

**Query used:**

```kql
DeviceFileEvents
| where DeviceName == 'ayaan-vm-soc'
| where FileName contains "tor"
| where Timestamp >= datetime(2026-06-06T15:16:51.7339925Z)
| order by Timestamp desc
```

<img width="2086" alt="DeviceFileEvents results" src="https://github.com/user-attachments/assets/78cfd2ba-a7a8-47c6-be3a-45940cb77bdc" />

---

### 2. Searched `DeviceProcessEvents` for Silent Installation

Searched for any `ProcessCommandLine` containing the TOR installer filename. At `2026-06-06T16:21:30Z`, `ayaanvm` (employee) executed `tor-browser-windows-x86_64-portable-15.0.15.exe` with the `/s` flag — a silent install that runs entirely in the background, bypassing any installation wizard and leaving no visible trace on screen.

**Query used:**

```kql
DeviceProcessEvents
| where DeviceName == 'ayaan-vm-soc'
| where ProcessCommandLine has_any("tor-browser-windows-x86_64-portable-15.0.15.exe")
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine, FolderPath, SHA256
```

<img width="1629" alt="Silent install process event" src="https://github.com/user-attachments/assets/7d3d7524-8cce-4162-baa1-2ccdaaa5d989" />

---

### 3. Searched `DeviceProcessEvents` for TOR Browser Execution

Searched for evidence that `ayaanvm` (employee) actually launched the TOR browser. The first `firefox.exe` process appeared at `2026-06-06T16:22:03Z`, followed by `tor.exe` at `2026-06-06T16:22:05Z`. A second wave of processes spawned between `16:22` and `16:25`, confirming the browser was opened and actively used across two separate sessions on the same afternoon.

**Query used:**

```kql
DeviceProcessEvents
| where DeviceName == "ayaan-vm-soc"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

<img width="1359" alt="TOR browser process creation" src="https://github.com/user-attachments/assets/e249a552-9c77-4546-9cdc-91b357142881" />

---

### 4. Searched `DeviceNetworkEvents` for TOR Network Connections

Searched for outbound connections on known TOR ports. At `2026-06-06T16:25:43Z`, `tor.exe` successfully connected to `87.120.8.91` on port `9001` — a known TOR relay port. The IP geolocates to Sofia, Bulgaria (Neterra Ltd., ASN 34224), carries a suspicious reputation score of 25/100 in Microsoft Defender, and had only been seen on this one device across the entire organisation, first observed just 14 hours prior. There were also additional connections — `firefox.exe` connected to `127.0.0.1:9151` at `16:22:06Z` and `127.0.0.1:9150` at `16:25:44Z`, confirming `ayaanvm` (employee) was actively routing traffic through the TOR network.

**Query used:**

```kql
DeviceNetworkEvents
| where DeviceName == "ayaan-vm-soc"
| where InitiatingProcessAccountName != "system"
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150, 9151, 443, 80)
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| order by Timestamp desc
```

<img width="1704" alt="TOR network connections" src="https://github.com/user-attachments/assets/480482b8-33d9-4940-96e0-fcd11182518f" />

---

## Chronological Event Timeline

### 1. TOR Installer Downloaded

- **Timestamp:** `2026-06-06T16:21:30Z`
- **Event:** User `ayaanvm` (employee) downloaded `tor-browser-windows-x86_64-portable-15.0.15.exe` to the Downloads folder on their corporate workstation.
- **Action:** File download detected.
- **File Path:** `C:\Users\ayaanVM\Downloads\tor-browser-windows-x86_64-portable-15.0.15.exe`

---

### 2. Silent Installation Executed

- **Timestamps:** `2026-06-06T16:21:35Z` and `2026-06-06T16:21:47Z`
- **Event:** User `ayaanvm` (employee) ran the installer with the `/s` flag, triggering a silent background install with no visible wizard or prompts. The TOR browser was installed directly to the Desktop without any indication to anyone nearby.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.15.exe /s`
- **File Path:** `C:\Users\ayaanVM\Downloads\tor-browser-windows-x86_64-portable-15.0.15.exe`

---

### 3. TOR Browser Launched

- **Timestamp:** `2026-06-06T16:22:03Z`
- **Event:** User `ayaanvm` (employee) opened the TOR browser. `firefox.exe` spawned at `16:22:03Z` followed immediately by `tor.exe` at `16:22:05Z`. Multiple additional child processes were created across two sessions between `16:22` and `16:25`.
- **Action:** Process creation of TOR-related executables detected.
- **File Paths:**  
  `C:\Users\ayaanVM\Desktop\Tor Browser\Browser\firefox.exe`  
  `C:\Users\ayaanVM\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

---

### 4. Connection to TOR Relay Node Confirmed

- **Timestamp:** `2026-06-06T16:25:43Z`
- **Event:** `tor.exe` successfully connected to `87.120.8.91` on port `9001`, a confirmed TOR relay node hosted in Sofia, Bulgaria. The IP had a suspicious reputation score of 25/100 in Microsoft Defender and had never been seen on any other device in the organisation prior to this incident.
- **Action:** ConnectionSuccess
- **Process:** `tor.exe`
- **File Path:** `C:\Users\ayaanVM\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

---

### 5. Additional TOR Browser Activity

- **Timestamps:**
  - `2026-06-06T16:22:06Z` — `firefox.exe` connected to `127.0.0.1:9151` (TOR control port)
  - `2026-06-06T16:22:37Z` — `firefox.exe` attempted connection to `127.0.0.1:9150` (failed — relay not yet ready)
  - `2026-06-06T16:25:44Z` — `firefox.exe` successfully connected to `127.0.0.1:9150` (TOR SOCKS proxy — browsing confirmed)
- **Event:** The failed connection at `16:22:37Z` followed by a successful one at `16:25:44Z` shows the employee waited for the TOR relay to establish before browsing, consistent with intentional and patient use of the TOR network rather than accidental execution.
- **Action:** Multiple connection attempts detected, final connection successful.

---

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2026-06-06T16:37:29Z`
- **Event:** User `ayaanvm` (employee) created a file named `tor-shopping-list.txt` in their Documents folder, along with a `.lnk` shortcut in AppData, potentially indicating notes or a list related to their TOR browsing activity.
- **Action:** File creation detected.
- **File Paths:**  
  `C:\Users\ayaanVM\Documents\tor-shopping-list.txt`  
  `C:\Users\ayaanVM\AppData\...\tor-shopping-list.lnk`

---

## Summary

In this simulated scenario, user `ayaanvm` (employee) on device `ayaan-vm-soc` downloaded and silently installed the TOR browser on 6 June 2026. The use of the `/s` install flag indicates deliberate intent to avoid detection. The employee launched the browser, connected to a TOR relay node in Sofia, Bulgaria (`87.120.8.91:9001`) — an IP with a suspicious reputation score of 25/100 that had never appeared elsewhere in the organisation — and was confirmed to be actively browsing anonymously through the TOR network via the local SOCKS proxy at `127.0.0.1:9150`. A failed connection attempt at `16:22:37Z` followed by a successful one at `16:25:44Z` shows the employee waited for the relay to establish before continuing. Following the session, the employee created a file named `tor-shopping-list.txt` in their Documents folder, suggesting the TOR browsing was purposeful and documented.

---

## Response Taken

TOR usage was confirmed on the corporate workstation `ayaan-vm-soc`. The device was isolated from the network and the employee's direct manager was notified.
