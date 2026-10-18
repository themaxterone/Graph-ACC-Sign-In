# Microsoft Graph User Sign-in Audit Tool (`graph_signins.py`)

A security-focused Python utility designed for SOC analysts, incident responders, and Entra ID administrators. It queries authentication events via the **Microsoft Graph API (`/auditLogs/signIns`)** using interactive PKCE authentication, exports structured CSV reports, and generates an interactive, client-side HTML dashboard.

---

## Table of Contents

1. [Features](#features)
2. [How It Works](#how-it-works)
3. [Prerequisites & Dependencies](#prerequisites--dependencies)
4. [Installation Guide](#installation-guide)
5. [Usage & Execution](#usage--execution)
6. [Execution Workflow & Outputs](#execution-workflow--outputs)

---

## Features

- **No Custom App Registration Needed**: Uses the pre-authorized, public Microsoft Azure CLI Client ID (`04b07795-8ddb-461a-bbee-02f9e1bf7b46`) with interactive browser-based PKCE login.
- **Account Selection Prompt**: Forces the Microsoft account picker (`prompt="select_account"`) to easily switch between administrative/analyst identities.
- **Automatic Email Normalization**: Trims whitespace and enforces lowercase conversion on target user inputs to ensure accurate OData querying.
- **Customizable Time Range (`-d` / `--days`)**: Queries sign-in events within a dynamic timeframe (defaults to the past 15 days).
- **Pagination Handling**: Transparently traverses `@odata.nextLink` to collect all historical sign-in logs within the selected scope.
- **Error Code Translation**: Maps common Microsoft Entra ID authentication error codes (e.g., `50126`, `50053`, `53003`) into clear, human-readable explanations.
- **Color-Coded Terminal Output**: Displays formatted event details directly in the console with status indicators (green for success, red with error reasons for failures).
- **Automated CSV Export**: Produces a timestamped, UTF-8-BOM encoded `.csv` file containing full event metadata.
- **Interactive HTML Dashboard**: Builds a self-contained report featuring real-time client-side search, summary metric cards, quick-filter buttons (*All / Success Only / Failures Only*), sticky headers, and sub-text error descriptions.
- **Corporate Proxy & SSL Ready**: Preconfigured with `verify=False` and suppressed warnings to operate cleanly within corporate networks undergoing SSL/TLS decryption.

---

## How It Works

1. **Interactive Authentication**: MSAL initializes a `PublicClientApplication` and requests the delegated scope `https://graph.microsoft.com/AuditLog.Read.All`. The local system launches the default web browser, allowing the analyst to authenticate and complete MFA.
2. **OData Query Construction**: A UTC-based cutoff timestamp is calculated using the configured day offset. An OData filter string is formed:
   ```text
   userPrincipalName eq '<user>' and createdDateTime ge <UTC_DATE>
   
---
   
## Prerequisites & Dependencies

- Python 3.8+ (or Anaconda / Miniconda)
- Required Python libraries:
  - `requests`
  - `urllib3`
  - `msal`
  
- Azure / Microsoft Entra ID Requirements
- Tenant License: Microsoft Entra ID P1 or P2 (or licensing suites such as Microsoft 365 E3/E5).
- Delegated Permission: AuditLog.Read.All (granted or consented within the tenant).

- Directory Roles (User Level): The analyst account performing the browser login must possess at least one of the following roles:
  -  `Security Reader (Recommended for SOC analysts)`

  -  `Reports Reader`

  -  `Global Reader`

  -  `Security Administrator`

  -  `Global Administrator`

---

## Installation Guide

### Using Anaconda (Recommended)

1. Open **Anaconda Prompt** from the Windows Start menu.
2. Install the necessary package:
```
conda install urllib3
pip install urllib3
```

---

## Usage & Execution

### 1. Default Query (Last 15 Days))

```
python graph_signins.py -u user@company.com
```

### 2. Custom Time Window (-d)

```
# Query the last 7 days
python graph_signins.py -u user@company.com -d 7

# Query the last 30 days
python graph_signins.py -u user@company.com -d 30
```

---

## Execution Workflow & Outputs

Authentication: A browser window will open automatically. Select your account and complete authentication/MFA.

Terminal Output: Results will stream in real time, outlining the date, application, IP, location, device details, and status for each sign-in.

CSV Export: Generated as signins_<user>_<days>d_<timestamp>.csv in the current working directory.

HTML Dashboard: Generated as signins_<user>_<days>d_<timestamp>.html. Double-click the file to open it in Microsoft Edge, Google Chrome, or any modern web browser to utilize interactive search and filtering.

---
