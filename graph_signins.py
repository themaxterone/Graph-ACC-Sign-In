import argparse
import csv
from datetime import datetime, timedelta, timezone
import html
import os
import sys
import msal
import requests
import urllib3

# Suppress SSL warnings in corporate environments with proxy inspection
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Microsoft Azure CLI official public Client ID
CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
AUTHORITY = "https://login.microsoftonline.com/organizations"
SCOPES = ["https://graph.microsoft.com/AuditLog.Read.All"]

# Catalog of common Microsoft Entra ID error codes
ENTRA_ERRORS = {
    50034: "The user account does not exist in the directory.",
    50053: "Account is temporarily locked out due to multiple failed password attempts.",
    50055: "The user's password has expired.",
    50057: "The user account is disabled.",
    50058: "Silent sign-in failed (user interaction required).",
    50074: "Multifactor authentication (MFA) is required.",
    50076: "Strong authentication (MFA) is required due to security policies.",
    50079: "The user must enroll in multifactor authentication.",
    50088: "The external user does not belong to the target tenant.",
    50126: "Invalid username or password.",
    50131: "The device does not comply with security policies or is not trusted.",
    50144: "Password has expired and must be reset.",
    53003: "Access blocked by Conditional Access policies.",
    70008: "Refresh token has expired.",
    70043: "Session revoked or terminated by the administrator."
}

def show_progress(step_name, current, total, bar_length=30):
    """Renders an inline real-time progress bar with percentage."""
    percent = float(current) * 100 / total if total > 0 else 100.0
    filled = int(bar_length * current // total) if total > 0 else bar_length
    bar = '█' * filled + '-' * (bar_length - filled)
    sys.stdout.write(f"\r[+] {step_name:<28} |{bar}| {percent:6.1f}% ({current}/{total})")
    sys.stdout.flush()
    if current >= total:
        sys.stdout.write("\n")

def get_access_token(verbose=False):
    """Acquires a delegated OAuth2 access token interactively using PKCE."""
    app = msal.PublicClientApplication(
        CLIENT_ID,
        authority=AUTHORITY
    )
    
    if verbose:
        print("\nOpening the browser for authentication...")
    result = app.acquire_token_interactive(
        scopes=SCOPES,
        prompt="select_account"
    )
    
    if "access_token" in result:
        if verbose:
            print("[+] Authentication successful.")
        return result["access_token"]
    else:
        error_msg = result.get("error_description", result.get("error"))
        print(f"\n\033[91m[!] Authentication error: {error_msg}\033[0m")
        sys.exit(1)

def parse_event(event):
    """Normalizes and parses sign-in log fields."""
    status_info = event.get("status", {})
    err_code = status_info.get("errorCode", 0)
    is_success = (err_code == 0)
    
    failure_reason_raw = status_info.get("failureReason") or ""
    if not is_success:
        if err_code in ENTRA_ERRORS:
            failure_desc = ENTRA_ERRORS[err_code]
        elif failure_reason_raw:
            failure_desc = failure_reason_raw
        else:
            failure_desc = "Unknown authentication error."
    else:
        failure_desc = ""

    location_info = event.get("location", {})
    city = location_info.get("city") or ""
    country = location_info.get("countryOrRegion") or ""
    if city and country:
        location = f"{city}, {country}"
    elif country:
        location = country
    else:
        location = city or "N/A"

    device_info = event.get("deviceDetail", {})
    os_name = device_info.get("operatingSystem") or "N/A"
    browser = device_info.get("browser") or "N/A"

    ca_policies = event.get("appliedConditionalAccessPolicies", [])
    ca_summary = []
    for policy in ca_policies:
        p_name = policy.get("displayName", "Unknown")
        p_result = policy.get("result", "N/A")
        ca_summary.append(f"{p_name} ({p_result})")
    
    ca_str = "; ".join(ca_summary) if ca_summary else "None / Not Applied"

    return {
        "datetime": event.get("createdDateTime", "N/A"),
        "user": event.get("userPrincipalName", "N/A"),
        "user_display": event.get("userDisplayName", "N/A"),
        "app": event.get("appDisplayName", "N/A"),
        "status": "Success" if is_success else "Failure",
        "is_success": is_success,
        "error_code": err_code,
        "failure_reason": failure_reason_raw,
        "failure_desc": failure_desc,
        "ip": event.get("ipAddress", "N/A"),
        "location": location,
        "os": os_name,
        "browser": browser,
        "ca": ca_str
    }

def export_to_csv(filename, records):
    """Saves records into a CSV file."""
    fields = [
        "Date and Time", "User", "APP", "Status", "ErrorCode",
        "Failure Meaning", "FailureReason Raw", "IP", "Location",
        "OS", "Device Browser", "Conditional Access"
    ]
    try:
        with open(filename, mode="w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            for r in records:
                writer.writerow({
                    "Date and Time": r["datetime"],
                    "User": r["user"],
                    "APP": r["app"],
                    "Status": r["status"],
                    "ErrorCode": r["error_code"],
                    "Failure Meaning": r["failure_desc"],
                    "FailureReason Raw": r["failure_reason"],
                    "IP": r["ip"],
                    "Location": r["location"],
                    "OS": r["os"],
                    "Device Browser": r["browser"],
                    "Conditional Access": r["ca"]
                })
        print(f"[+] CSV file generated: \033[1m{filename}\033[0m")
    except Exception as e:
        print(f"\033[91m[!] Error exporting CSV: {e}\033[0m")

def export_to_html(filename, user, days, records):
    """Generates an interactive dashboard in HTML format."""
    total = len(records)
    success_count = sum(1 for r in records if r["is_success"])
    failure_count = total - success_count

    rows_html = []
    for r in records:
        if r["is_success"]:
            status_cell = '<span class="badge badge-success">Success</span>'
        else:
            status_cell = f"""
            <span class="badge badge-danger">Failure ({r['error_code']})</span>
            <div class="failure-desc">{html.escape(r['failure_desc'])}</div>
            """

        rows_html.append(f"""
        <tr data-status="{r['status']}">
            <td class="font-mono text-nowrap">{html.escape(r['datetime'])}</td>
            <td><strong>{html.escape(r['user'])}</strong><br><small class="text-muted">{html.escape(r['user_display'])}</small></td>
            <td>{html.escape(r['app'])}</td>
            <td class="status-cell">{status_cell}</td>
            <td class="font-mono">{html.escape(r['ip'])}</td>
            <td>{html.escape(r['location'])}</td>
            <td>{html.escape(r['os'])}</td>
            <td>{html.escape(r['browser'])}</td>
            <td class="ca-cell">{html.escape(r['ca'])}</td>
        </tr>
        """)

    template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign-in Audit Logs - {html.escape(user)}</title>
    <style>
        :root {{
            --bg-primary: #f8fafc;
            --surface: #ffffff;
            --text-main: #0f172a;
            --text-muted: #64748b;
            --border-color: #e2e8f0;
            --primary: #2563eb;
            --success: #16a34a;
            --danger: #dc2626;
            --success-bg: #dcfce7;
            --danger-bg: #fee2e2;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-main);
            padding: 24px;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 16px;
            margin-bottom: 24px;
        }}
        .header h1 {{ font-size: 1.5rem; font-weight: 700; }}
        .header p {{ color: var(--text-muted); font-size: 0.9rem; }}
        .stats {{
            display: flex;
            gap: 12px;
        }}
        .stat-card {{
            background: var(--surface);
            padding: 10px 18px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            display: flex;
            flex-direction: column;
            align-items: center;
        }}
        .stat-card .num {{ font-size: 1.25rem; font-weight: 700; }}
        .stat-card .label {{ font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; }}
        .controls {{
            display: flex;
            gap: 12px;
            margin-bottom: 16px;
            flex-wrap: wrap;
        }}
        .search-box {{
            flex: 1;
            min-width: 250px;
            padding: 10px 14px;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            font-size: 0.9rem;
            outline: none;
        }}
        .search-box:focus {{ border-color: var(--primary); }}
        .filter-btn {{
            background: var(--surface);
            border: 1px solid var(--border-color);
            padding: 8px 14px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.85rem;
            font-weight: 600;
        }}
        .filter-btn.active {{
            background: var(--primary);
            color: white;
            border-color: var(--primary);
        }}
        .table-container {{
            background: var(--surface);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: auto;
            max-height: 75vh;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 0.85rem;
        }}
        thead {{
            position: sticky;
            top: 0;
            background: #f1f5f9;
            z-index: 10;
        }}
        th {{
            padding: 12px 14px;
            font-weight: 600;
            color: #334155;
            border-bottom: 2px solid var(--border-color);
            white-space: nowrap;
        }}
        td {{
            padding: 12px 14px;
            border-bottom: 1px solid var(--border-color);
            vertical-align: top;
        }}
        tr:hover {{ background-color: #f8fafc; }}
        .status-cell {{
            min-width: 190px;
            max-width: 260px;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 12px;
            font-weight: 600;
            font-size: 0.75rem;
            text-align: center;
        }}
        .badge-success {{ background-color: var(--success-bg); color: var(--success); }}
        .badge-danger {{ background-color: var(--danger-bg); color: var(--danger); }}
        .failure-desc {{
            font-size: 0.72rem;
            color: #991b1b;
            margin-top: 5px;
            line-height: 1.3;
            background: #fef2f2;
            padding: 4px 6px;
            border-radius: 4px;
            border-left: 2px solid #ef4444;
            word-break: break-word;
        }}
        .font-mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 0.8rem; }}
        .text-nowrap {{ white-space: nowrap; }}
        .text-muted {{ color: var(--text-muted); }}
        .ca-cell {{ max-width: 280px; word-break: break-word; font-size: 0.78rem; color: #475569; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>User Sign-in Logs</h1>
            <p>User: <strong>{html.escape(user)}</strong> | Last {days} days</p>
        </div>
        <div class="stats">
            <div class="stat-card">
                <span class="num">{total}</span>
                <span class="label">Total</span>
            </div>
            <div class="stat-card">
                <span class="num" style="color: var(--success);">{success_count}</span>
                <span class="label">Success</span>
            </div>
            <div class="stat-card">
                <span class="num" style="color: var(--danger);">{failure_count}</span>
                <span class="label">Failures</span>
            </div>
        </div>
    </div>

    <div class="controls">
        <input type="text" id="searchInput" class="search-box" placeholder="Search by IP, app, browser, date, error...">
        <button class="filter-btn active" onclick="filterStatus('all', this)">All</button>
        <button class="filter-btn" onclick="filterStatus('Success', this)">Success Only</button>
        <button class="filter-btn" onclick="filterStatus('Failure', this)">Failures Only</button>
    </div>

    <div class="table-container">
        <table id="logsTable">
            <thead>
                <tr>
                    <th>Date and Time</th>
                    <th>User</th>
                    <th>APP</th>
                    <th>Status</th>
                    <th>IP</th>
                    <th>Location</th>
                    <th>OS</th>
                    <th>Device Browser</th>
                    <th>Conditional Access</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows_html)}
            </tbody>
        </table>
    </div>

    <script>
        const searchInput = document.getElementById('searchInput');
        const rows = document.querySelectorAll('#logsTable tbody tr');
        let currentStatusFilter = 'all';

        function applyFilters() {{
            const query = searchInput.value.toLowerCase();
            rows.forEach(row => {{
                const matchSearch = row.innerText.toLowerCase().includes(query);
                const rowStatus = row.getAttribute('data-status');
                const matchStatus = (currentStatusFilter === 'all') || (rowStatus === currentStatusFilter);
                row.style.display = (matchSearch && matchStatus) ? '' : 'none';
            }});
        }}

        searchInput.addEventListener('input', applyFilters);

        function filterStatus(status, btn) {{
            currentStatusFilter = status;
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            applyFilters();
        }}
    </script>
</body>
</html>
"""
    try:
        with open(filename, mode="w", encoding="utf-8") as f:
            f.write(template)
        print(f"[+] HTML report generated: \033[1m{filename}\033[0m")
    except Exception as e:
        print(f"\033[91m[!] Error exporting HTML: {e}\033[0m")

def get_user_signins(user, days=15, verbose=False):
    user = user.strip().lower()

    if not verbose:
        show_progress("1/4 Authentication", 1, 1)

    token = get_access_token(verbose)
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
    filter_date = cutoff_date.strftime("%Y-%m-%dT%H:%M:%SZ")

    odata_filter = f"userPrincipalName eq '{user}' and createdDateTime ge {filter_date}"
    url = f"https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter={odata_filter}&$top=100"

    all_events = []
    if verbose:
        print(f"\n[+] Querying sign-in logs for '{user}' (last {days} days, since {filter_date})...")

    while url:
        try:
            if not verbose:
                show_progress("2/4 Fetching Graph logs", len(all_events), len(all_events) + 100)
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            data = response.json()
            batch = data.get("value", [])
            all_events.extend(batch)
            url = data.get("@odata.nextLink", None)
        except requests.exceptions.RequestException as e:
            print(f"\n\033[91m[!] Microsoft Graph API error: {e}\033[0m")
            if hasattr(e, 'response') and e.response is not None:
                print(f"Details: {e.response.text}")
            break

    if not verbose:
        show_progress("2/4 Fetching Graph logs", len(all_events), len(all_events))

    if not all_events:
        print(f"\nNo sign-in events found for '{user}' in the last {days} days.")
        return

    parsed_records = [parse_event(ev) for ev in all_events]

    # Imprimir registros individuales solo si -v está habilitado
    if verbose:
        print("\n" + "=" * 80)
        print(f" TOTAL SIGN-IN EVENTS FOUND ({days} DAYS): {len(parsed_records)}")
        print("=" * 80)
        for r in parsed_records:
            if r["is_success"]:
                status_text = "\033[92mSuccess\033[0m"
            else:
                status_text = f"\033[91mFailure (Code: {r['error_code']})\033[0m\n  ↳ \033[2mReason: {r['failure_desc']}\033[0m"

            print(f"[{r['datetime']}] {r['user']} | {r['app']}")
            print(f"  Status  : {status_text}")
            print(f"  IP/Loc  : {r['ip']} ({r['location']}) | OS: {r['os']} | Browser: {r['browser']}")
            print(f"  CA      : {r['ca']}")
            print("-" * 80)

    # Cálculo del resumen final
    total_logins = len(parsed_records)
    success_logins = sum(1 for r in parsed_records if r["is_success"])
    failed_logins = total_logins - success_logins
    unique_ips = len(set(r["ip"] for r in parsed_records if r["ip"] and r["ip"] != "N/A"))

    # Cuadro resumen siempre presente al final
    print("\n" + "=" * 85)
    print(f" SIGN-IN EVENTS SUMMARY ({days} DAYS) | UNIQUE IPs CHECKED: {unique_ips}")
    print("=" * 85)
    print(f" Total Logins   : {total_logins}")
    print(f" Successful     : \033[92m{success_logins}\033[0m")
    print(f" Failed         : \033[91m{failed_logins}\033[0m")
    print(f" Unique IPs     : {unique_ips}")
    print("=" * 85 + "\n")

    user_slug = user.replace("@", "_").replace(".", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    csv_filename = f"signins_{user_slug}_{days}d_{timestamp}.csv"
    html_filename = f"signins_{user_slug}_{days}d_{timestamp}.html"

    if not verbose:
        show_progress("3/4 Exporting CSV", 1, 1)
    export_to_csv(csv_filename, parsed_records)

    if not verbose:
        show_progress("4/4 Exporting HTML", 1, 1)
    export_to_html(html_filename, user, days, parsed_records)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Query Microsoft Graph sign-in logs and export to CSV + interactive HTML.")
    parser.add_argument("-u", "--user", required=True, help="UserPrincipalName / corporate email of the user")
    parser.add_argument("-d", "--days", type=int, default=15, help="Number of past days to query (default: 15)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode: Print full event-by-event details to terminal")
    args = parser.parse_args()

    get_user_signins(args.user.strip().lower(), args.days, args.verbose)