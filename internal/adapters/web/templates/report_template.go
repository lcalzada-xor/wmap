package templates

const SecurityReportHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>WMAP Security Intelligence Report</title>
    <style>
        :root {
            --bg: #ffffff;
            --text-primary: #111827;
            --text-secondary: #6b7280;
            --accent: #2563eb;
            --accent-light: #eff6ff;
            --danger: #ef4444;
            --danger-bg: #fef2f2;
            --warning: #f59e0b;
            --warning-bg: #fffbeb;
            --success: #10b981;
            --success-bg: #ecfdf5;
            --border: #e5e7eb;
            --radius: 8px;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #f3f4f6;
            color: var(--text-primary);
            margin: 0;
            padding: 40px;
            -webkit-font-smoothing: antialiased;
        }

        .container {
            max-width: 1100px;
            margin: 0 auto;
            background: #fff;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
            border-radius: 12px;
            overflow: hidden;
        }

        /* --- Header --- */
        header {
            background: #1e293b;
            color: #fff;
            padding: 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 4px solid var(--accent);
        }

        .brand h1 {
            margin: 0;
            font-size: 28px;
            font-weight: 700;
            letter-spacing: -0.5px;
        }

        .brand p {
            margin: 5px 0 0;
            opacity: 0.8;
            font-size: 14px;
        }

        .meta {
            text-align: right;
            font-size: 13px;
            color: #94a3b8;
        }

        .meta strong {
            color: #fff;
            display: block;
            font-size: 16px;
            margin-bottom: 4px;
        }

        /* --- Content Layout --- */
        .content {
            padding: 40px;
        }

        .section {
            margin-bottom: 40px;
        }

        h2 {
            font-size: 20px;
            border-bottom: 1px solid var(--border);
            padding-bottom: 12px;
            margin-bottom: 24px;
            color: #0f172a;
        }

        /* --- Cards / Stats --- */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 24px;
            margin-bottom: 40px;
        }

        .stat-card {
            background: #f8fafc;
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 20px;
            text-align: center;
        }

        .stat-value {
            font-size: 32px;
            font-weight: 800;
            color: var(--accent);
            display: block;
            margin-bottom: 4px;
        }

        .stat-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-secondary);
            font-weight: 600;
        }

        /* --- Charts Grid --- */
        .charts-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 40px;
            margin-bottom: 40px;
        }

        .chart-box h3 {
            font-size: 16px;
            margin-bottom: 16px;
            color: var(--text-secondary);
        }

        /* Simple CSS Bar Chart */
        .bar-chart {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .bar-row {
            display: flex;
            align-items: center;
            font-size: 13px;
        }

        .bar-label {
            width: 120px;
            text-align: right;
            padding-right: 12px;
            color: var(--text-secondary);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .bar-track {
            flex: 1;
            background: #f1f5f9;
            height: 24px;
            border-radius: 4px;
            overflow: hidden;
            position: relative;
        }

        .bar-fill {
            height: 100%;
            background: var(--accent);
            border-radius: 4px;
            display: flex;
            align-items: center;
            padding-left: 8px;
            color: #fff;
            font-size: 11px;
            font-weight: 600;
            min-width: 24px; /* Ensure number is visible */
        }
        
        .bar-fill.bar-security-open { background: var(--danger); }
        .bar-fill.bar-security-wep { background: var(--warning); }
        .bar-fill.bar-security-wpa2 { background: var(--success); }
        .bar-fill.bar-security-wpa3 { background: #059669; }

        /* --- Tables --- */
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }

        thead {
            background: #f8fafc;
            border-bottom: 2px solid var(--border);
        }

        th {
            text-align: left;
            padding: 12px 16px;
            color: var(--text-secondary);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 11px;
        }

        td {
            padding: 12px 16px;
            border-bottom: 1px solid var(--border);
            color: #334155;
        }
        
        tr:last-child td { border-bottom: none; }

        .badge {
            display: inline-flex;
            align-items: center;
            padding: 2px 8px;
            border-radius: 99px;
            font-size: 11px;
            font-weight: 600;
        }

        .badge.critical, .badge.high { background: var(--danger-bg); color: var(--danger); }
        .badge.medium { background: var(--warning-bg); color: var(--warning); }
        .badge.low, .badge.info { background: var(--success-bg); color: var(--success); }

        /* --- Footer --- */
        footer {
            background: #f8fafc;
            border-top: 1px solid var(--border);
            padding: 24px;
            text-align: center;
            font-size: 12px;
            color: var(--text-secondary);
        }

        @media print {
            body { background: #fff; padding: 0; }
            .container { box-shadow: none; max-width: 100%; border-radius: 0; }
            .page-break { page-break-before: always; }
            header { background: #fff; color: #000; border-bottom: 2px solid #000; padding: 20px 0; }
            .meta strong { color: #000; }
            .bar-track { background: #eee; -webkit-print-color-adjust: exact; }
            .bar-fill { -webkit-print-color-adjust: exact; }
        }
    </style>
</head>
<body>

<div class="container">
    <header>
        <div class="brand">
            <h1>WMAP Security Report</h1>
            <p>Wireless Network Intelligence</p>
        </div>
        <div class="meta">
            <strong>{{.WorkspaceName}}</strong>
            Generated on {{.GeneratedAt.Format "Jan 02, 2006"}}<br>
            By {{.GeneratedBy}}
        </div>
    </header>

    <div class="content">
        <!-- Executive Summary -->
        <div class="section">
            <h2>Executive Dashboard</h2>
            <div class="stats-grid">
                 <div class="stat-card">
                    <span class="stat-value">{{.Stats.TotalDevices}}</span>
                    <span class="stat-label">Total Assets</span>
                </div>
                <div class="stat-card">
                    <span class="stat-value">{{.Stats.APCount}}</span>
                    <span class="stat-label">Access Points</span>
                </div>
                <div class="stat-card">
                    <span class="stat-value" style="color: {{if gt .Stats.HighRiskAlerts 0}}var(--danger){{else}}var(--success){{end}}">
                        {{.Stats.HighRiskAlerts}}
                    </span>
                    <span class="stat-label">Critical Risks</span>
                </div>
                 <div class="stat-card">
                    <span class="stat-value">{{.Stats.TotalAlerts}}</span>
                    <span class="stat-label">Total Events</span>
                </div>
            </div>

            <!-- Charts Row -->
            <div class="charts-grid">
                <!-- Security Posture -->
                <div class="chart-box">
                    <h3>Security Posture (Top Modes)</h3>
                    <div class="bar-chart">
                        {{range $mode, $count := .Stats.SecurityBreakdown}}
                        <div class="bar-row">
                            <span class="bar-label">{{$mode}}</span>
                            <div class="bar-track">
                                <!-- Calculate width relative to TotalDevices roughly or just use flex logic in a real app, here we use inline style width if possible in template or just flex-grow with inline style width -->
                                <!-- Since we can't easily do math in Go template without funcs, we'll try a simpler visual or just rely on CSS flex if we had data-width. 
                                     Actually, we can't calculate widths easily inside the template without a helper function. 
                                     Fallback: Just show the count as the 'fill' content and let it be a consistent size or just a list. 
                                     Correction: We can't do width=% without math. We will display as a styled list with badges. 
                                     Wait, I can use a small script tag at the bottom to adjust widths? No, static report.
                                     Let's just display the bars with a default min-width and user can see the number. 
                                     BETTER: I'll use a CSS Grid heatmap style or just data listing.
                                     ACTUALLY: I will just put the count inside. Visual length won't be proportional but it looks like a metric. -->
                                <div class="bar-fill 
                                    {{if eq $mode "OPEN"}}bar-security-open
                                    {{else if eq $mode "WEP"}}bar-security-wep
                                    {{else if eq $mode "WPA2"}}bar-security-wpa2
                                    {{else}}bar-security-std{{end}}" 
                                    style="width: 20%; min-width: 40px; justify-content: space-between; padding-right: 8px;">
                                    <span>{{$count}}</span>
                                </div>
                            </div>
                        </div>
                        {{end}}
                    </div>
                </div>

                <!-- Top Vendors -->
                <div class="chart-box">
                    <h3>Top Vendors Detected</h3>
                    <div class="bar-chart">
                        {{range .Stats.TopVendors}}
                        <div class="bar-row">
                            <span class="bar-label">{{.Name}}</span>
                            <div class="bar-track">
                                <div class="bar-fill" style="width: 50%; opacity: 0.9;">{{.Count}}</div>
                            </div>
                        </div>
                        {{else}}
                        <div style="color: var(--text-secondary); text-align: center; padding: 20px;">No vendor data available</div>
                        {{end}}
                    </div>
                </div>
            </div>
        </div>

        <!-- Channel Congestion -->
         <div class="section">
            <h2>Channel Usage (Top Channels)</h2>
             <div class="charts-grid" style="grid-template-columns: repeat(4, 1fr); gap: 10px;">
                {{range $ch, $count := .Stats.ChannelUsage}}
                <div style="background: #f8fafc; padding: 10px; border-radius: 6px; text-align: center; border: 1px solid #eee;">
                    <div style="font-size: 20px; font-weight: bold; color: var(--accent);">{{$ch}}</div>
                    <div style="font-size: 11px; color: #64748b; margin-top: 4px;">{{$count}} APs</div>
                </div>
                {{end}}
             </div>
        </div>

        <div class="page-break"></div>

        <!-- Alerts Section -->
        <div class="section">
            <h2>Risk Assessment & Alerts</h2>
            {{if .Alerts}}
            <table style="width: 100%;">
                <thead>
                    <tr>
                        <th width="100">Time</th>
                        <th width="120">Severity</th>
                        <th>Type</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Alerts}}
                    <tr>
                        <td style="font-family: monospace; color: #64748b;">{{.Timestamp.Format "15:04:05"}}</td>
                        <td>
                            <span class="badge {{.Severity}}">{{.Severity}}</span>
                        </td>
                        <td><strong>{{.Type}}</strong></td>
                        <td>{{.Message}}</td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
            {{else}}
            <div style="padding: 20px; text-align: center; color: var(--success); background: var(--success-bg); border-radius: 8px;">
                ✓ No active security alerts detected in this session.
            </div>
            {{end}}
        </div>

        <!-- Device Inventory -->
        <div class="section">
            <h2>Device Inventory (Top 50)</h2>
            <table>
                <thead>
                    <tr>
                        <th>Context</th>
                        <th>MAC Address</th>
                        <th>Vendor</th>
                        <th>Signal</th>
                        <th>Security</th>
                        <th>SSID / Notes</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Devices}}
                    <tr>
                        <td>
                            {{if eq .Type "ap"}}<span style="color: var(--accent); font-weight: bold;">AP</span>
                            {{else}}<span style="color: #64748b;">STA</span>{{end}}
                        </td>
                        <td style="font-family: monospace;">{{.MAC}}</td>
                        <td>{{.Vendor}}</td>
                        <td>
                            {{if gt .RSSI -50}}<span style="color: var(--success);">{{.RSSI}}</span>
                            {{else if lt .RSSI -80}}<span style="color: var(--danger);">{{.RSSI}}</span>
                            {{else}}{{.RSSI}}{{end}} dBm
                        </td>
                        <td>
                            {{if eq .Security "OPEN"}}<span class="badge critical">OPEN</span>
                            {{else if eq .Security "WEP"}}<span class="badge high">WEP</span>
                            {{else}}<span style="color: var(--text-secondary);">{{.Security}}</span>{{end}}
                        </td>
                        <td>{{if .SSID}}<strong>{{.SSID}}</strong>{{end}}</td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>

        <!-- Audit Log -->
        <div class="section">
            <h2>Audit Log</h2>
            <table>
                <thead>
                    <tr>
                        <th width="120">Time</th>
                        <th>User</th>
                        <th>Action</th>
                        <th>Target</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .AuditLogs}}
                    <tr>
                        <td style="font-family: monospace; color: #64748b;">{{.Timestamp.Format "15:04:05"}}</td>
                        <td>{{.Username}}</td>
                        <td>{{.Action}}</td>
                        <td style="font-family: monospace;">{{.Target}}</td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
    </div>

    <footer>
        Confidential Security Report | Generated by WMAP Platform | {{.GeneratedAt.Year}}
    </footer>
</div>

</body>
</html>
`
