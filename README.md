# Microsoft Graph User Sign-in Audit Tool (`graph_signins.py`)

A security-focused Python utility designed for SOC analysts, incident responders, and Entra ID administrators[cite: 6]. It queries authentication events via the **Microsoft Graph API (`/auditLogs/signIns`)** using interactive PKCE authentication[cite: 6], exports structured CSV reports[cite: 6], and generates an interactive, client-side HTML dashboard[cite: 6].

---

## Table of Contents

1. [Features](#1-features)
2. [How It Works](#2-how-it-works)
3. [Prerequisites & Dependencies](#3-prerequisites--dependencies)
4. [Installation Guide](#4-installation-guide)
   - [Option 1: Using Anaconda (Recommended)](#option-1-using-anaconda-recommended)
   - [Option 2: Using Standard Python (CMD / PowerShell / Bash)](#option-2-using-standard-python-cmd--powershell--bash)
5. [Usage & Execution](#5-usage--execution)
   - [1. Default Query (Last 15 Days, Quiet Progress Mode)](#1-default-query-last-15-days-quiet-progress-mode)
   - [2. Custom Time Window (-d)](#2-custom-time-window--d)
   - [3. Verbose Mode (-v)](#3-verbose-mode--v)
   - [Command-Line Arguments Reference](#command-line-arguments-reference)
6. [Generated Outputs](#6-generated-outputs)
7. [Corporate Proxy & SSL Troubleshooting](#7-corporate-proxy--ssl-troubleshooting)

---

## 1. Features

- **No Custom App Registration Needed**: Uses the pre-authorized, public Microsoft Azure CLI Client ID (`04b07795-8ddb-461a-bbee-02f9e1bf7b46`) with interactive browser-based PKCE login[cite: 6].
- **Account Selection Prompt**: Forces the Microsoft account picker (`prompt="select_account"`) to easily select or switch between administrative/analyst identities[cite: 6].
- **Automatic Email Normalization**: Trims whitespace and enforces lowercase conversion on target user inputs to ensure accurate OData querying[cite: 6].
- **Customizable Time Range (`-d` / `--days`)**: Queries sign-in events within a dynamic timeframe (defaults to the past 15 days)[cite: 6].
- **Transparent Pagination**: Traverses `@odata.nextLink` automatically to collect all historical sign-in logs matching the criteria[cite: 6].
- **Error Code Translation**: Maps common Microsoft Entra ID authentication error codes (e.g., `50126`, `50053`, `53003`) into clear, human-readable explanations[cite: 6].
- **Dual Console Modes**:
  - **Quiet Mode (Default)**: Inline real-time progress bars for each stage (*Authentication*, *Fetching Graph logs*, *Exporting CSV*, *Exporting HTML*) followed by a final summary box[cite: 6].
  - **Verbose Mode (`-v`)**: Real-time event-by-event terminal breakdown with color-coded status indicators (green for success, red with error reasons for failures)[cite: 6].
- **Automated CSV Export**: Produces a timestamped, UTF-8-BOM encoded `.csv` file containing full event metadata[cite: 6].
- **Interactive HTML Dashboard**: Builds a self-contained report featuring real-time client-side search, summary metric cards, quick-filter buttons (*All / Success Only / Failures Only*), sticky headers, and sub-text error descriptions[cite: 6].
- **Corporate Proxy & SSL Ready**: Preconfigured with `verify=False` and suppressed warnings to operate cleanly within corporate networks undergoing SSL/TLS decryption[cite: 6].

---

## 2. How It Works

1. **Interactive Authentication**: MSAL initializes a `PublicClientApplication` and requests the delegated scope `https://graph.microsoft.com/AuditLog.Read.All`[cite: 6]. The local system launches the default web browser, allowing the analyst to authenticate and complete MFA[cite: 6].
2. **OData Query Construction**: A UTC-based cutoff timestamp is calculated using the configured day offset[cite: 6]. An OData filter string is formed[cite: 6]:
   ```text
   userPrincipalName eq '<user>' and createdDateTime ge <UTC_DATE>
   ```
3. **Log Retrieval & Pagination**: The script performs HTTP GET requests to `https://graph.microsoft.com/v1.0/auditLogs/signIns`[cite: 6]. If the response contains `@odata.nextLink`, additional pages are retrieved until the log history is exhausted[cite: 6].
4. **Data Extraction & Normalization**: Each log entry is parsed to extract[cite: 6]:
   - Date and time (UTC)[cite: 6]
   - Application name (`appDisplayName`)[cite: 6]
   - IP address and geographic location (City, Country)[cite: 6]
   - Operating system and browser (`deviceDetail`)[cite: 6]
   - Status (Success or Failure with internal code and explanation)[cite: 6]
   - Applied Conditional Access policies and evaluation results[cite: 6]
5. **Report Generation**: The parsed records are summarized in the console and written to both `signins_<user>_<days>d_<timestamp>.csv` and `signins_<user>_<days>d_<timestamp>.html`[cite: 6].

---

## 3. Prerequisites & Dependencies

### Python Environment
- Python 3.8+ (Standard Python or Anaconda/Miniconda)[cite: 6]
- Required Python packages[cite: 6]:
  - `msal`[cite: 6]
  - `requests`[cite: 6]
  - `urllib3`[cite: 6]

### Azure / Microsoft Entra ID Requirements
- **Tenant License**: Microsoft Entra ID P1 or P2 (or licensing suites such as Microsoft 365 E3/E5)[cite: 6].
- **Delegated Permission**: `AuditLog.Read.All` (granted or consented within the tenant)[cite: 6].
- **Directory Roles (User Level)**: The analyst account performing the browser login must possess at least one of the following roles[cite: 6]:
  - *Security Reader* (Recommended for SOC analysts)[cite: 6]
  - *Reports Reader*[cite: 6]
  - *Global Reader*[cite: 6]
  - *Security Administrator*[cite: 6]
  - *Global Administrator*[cite: 6]

---

## 4. Installation Guide

### Option 1: Using Anaconda (Recommended)

1. Open **Anaconda Prompt**[cite: 6].
2. Install the required dependencies[cite: 6]:
   ```bash
   conda install requests
   pip install msal urllib3
   ```
   *(Confirm with `y` if prompted)*.

### Option 2: Using Standard Python (CMD / PowerShell / Bash)

1. Open your terminal or PowerShell console.
2. Install dependencies via `pip`[cite: 6]:
   ```bash
   pip install msal requests urllib3
   ```

---

## 5. Usage & Execution

Navigate to the directory containing `graph_signins.py`[cite: 6]:
```cmd
cd "C:\Path\To\Script"
```

### 1. Default Query (Last 15 Days, Quiet Progress Mode)
To inspect an account over the default 15-day window with progress bars[cite: 6]:
```bash
python graph_signins.py -u user@company.com
```

### 2. Custom Time Window (-d)
To extend or narrow the search timeframe, supply the `-d` argument followed by the number of days[cite: 6]:
```bash
# Query the last 7 days
python graph_signins.py -u user@company.com -d 7

# Query the last 30 days
python graph_signins.py -u user@company.com -d 30
```

### 3. Verbose Mode (-v)
Enables detailed event-by-event terminal output in real time[cite: 6]:
```bash
python graph_signins.py -u user@company.com -v
python graph_signins.py -u user@company.com -d 30 -v
```

### Command-Line Arguments Reference

| Argument | Type | Default | Required | Description |
| :--- | :--- | :--- | :--- | :--- |
| `-u`, `--user` | String | *None* | **Yes** | Target UserPrincipalName or corporate email address[cite: 6]. |
| `-d`, `--days` | Integer | `15` | No | Number of past days to inspect from current UTC time[cite: 6]. |
| `-v`, `--verbose` | Flag | `False` | No | Enables detailed event-by-event output in terminal[cite: 6]. |

---

## 6. Generated Outputs

### 1. Terminal Summary Box
Always displayed at the end of the execution[cite: 6]:
```text
=====================================================================================
 SIGN-IN EVENTS SUMMARY (15 DAYS) | UNIQUE IPs CHECKED: 3
=====================================================================================
 Total Logins   : 25
 Successful     : 23
 Failed         : 2
 Unique IPs     : 3
=====================================================================================
```

### 2. CSV Report (`signins_<user>_<days>d_<timestamp>.csv`)
Full tabular event export suitable for Excel or SIEM ingestion, including: `Date and Time`, `User`, `APP`, `Status`, `ErrorCode`, `Failure Meaning`, `FailureReason Raw`, `IP`, `Location`, `OS`, `Device Browser`, and `Conditional Access`[cite: 6].

### 3. Interactive HTML Dashboard (`signins_<user>_<days>d_<timestamp>.html`)
Standalone report viewable in any modern web browser featuring[cite: 6]:
- Summary metric cards (*Total*, *Success*, *Failures*)[cite: 6].
- Real-time instant search by IP, app, browser, date, error reason[cite: 6].
- One-click filters (*All / Success Only / Failures Only*)[cite: 6].
- Error explanations highlighted under failed login codes[cite: 6].

---

## 7. Corporate Proxy & SSL Troubleshooting

When executing this script in corporate environments with SSL/TLS inspection, certificate verification errors may occur[cite: 6]. The script natively handles this behavior by[cite: 6]:
1. Disabling insecure request warnings[cite: 6]:
   ```python
   import urllib3
   urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
   ```
2. Setting `verify=False` within outbound Microsoft Graph requests[cite: 6]:
   ```python
   requests.get(url, headers=headers, verify=False)
   ```