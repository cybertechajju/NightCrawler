"""
NightCrawler v2.5 - Professional HTML Report Generator
Multiple templates: HackerOne, BugCrowd, Email Format
by CyberTechAjju | Keep Learning // Keep Hacking
"""

from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass
from datetime import datetime
import html
import json


@dataclass
class ReportConfig:
    """Configuration for report generation"""
    reporter_name: str = "CyberTechAjju"
    reporter_email: str = ""
    reporter_username: str = ""
    program_name: str = ""
    template: str = "hackerone"  # hackerone, bugcrowd, email
    include_poc: bool = True
    include_remediation: bool = True


# Impact Analysis Database - Maps finding types to impacts
IMPACT_DATABASE = {
    # API Keys & Tokens
    "AWS Access Key": {
        "severity": "CRITICAL",
        "cvss": "9.8",
        "impact": "Full AWS account takeover. Attacker can access S3 buckets, EC2 instances, RDS databases, and all AWS resources. Can lead to massive data breach, crypto mining, or complete infrastructure compromise.",
        "remediation": "1. Immediately rotate the exposed key in AWS IAM console\n2. Review CloudTrail logs for unauthorized access\n3. Implement secrets management (AWS Secrets Manager, HashiCorp Vault)\n4. Never hardcode credentials in source code"
    },
    "AWS Secret Key": {
        "severity": "CRITICAL",
        "cvss": "9.8",
        "impact": "Combined with Access Key, provides full AWS account control. Can lead to data exfiltration, resource hijacking, and financial damage through unauthorized resource usage.",
        "remediation": "1. Rotate AWS credentials immediately\n2. Enable MFA on AWS accounts\n3. Use IAM roles instead of long-term credentials\n4. Implement least privilege access"
    },
    "GitHub Token": {
        "severity": "HIGH",
        "cvss": "8.6",
        "impact": "Access to private repositories, ability to push malicious code, steal source code and secrets, create backdoors in CI/CD pipelines.",
        "remediation": "1. Revoke token immediately on GitHub\n2. Audit repository access logs\n3. Use fine-grained personal access tokens\n4. Implement secret scanning in CI/CD"
    },
    "GitHub Personal Access Token": {
        "severity": "HIGH",
        "cvss": "8.6",
        "impact": "Full access to user's GitHub account based on token scopes. Can read/write repositories, manage organizations, and access sensitive data.",
        "remediation": "1. Revoke the PAT from GitHub Settings > Developer Settings\n2. Review recent activity on the account\n3. Use tokens with minimal required scopes\n4. Set token expiration dates"
    },
    "Stripe API Key": {
        "severity": "CRITICAL",
        "cvss": "9.1",
        "impact": "Access to payment processing. Attacker can view customer payment data, issue refunds, create charges, or steal financial information. Direct financial and compliance impact.",
        "remediation": "1. Roll the API key in Stripe Dashboard\n2. Review recent transactions for anomalies\n3. Enable restricted API keys for specific operations\n4. Implement webhook signature verification"
    },
    "Firebase Config": {
        "severity": "HIGH",
        "cvss": "7.5",
        "impact": "Access to Firebase database, authentication, and cloud functions. Can lead to user data exposure, authentication bypass, and database manipulation.",
        "remediation": "1. Review and tighten Firebase security rules\n2. Implement proper authentication checks\n3. Use Firebase App Check for additional security\n4. Monitor Firebase console for unusual activity"
    },
    "Google API Key": {
        "severity": "MEDIUM",
        "cvss": "6.5",
        "impact": "Depending on enabled APIs, can lead to quota theft, unauthorized API usage, access to Google Cloud resources, or exposure of user data through enabled services.",
        "remediation": "1. Restrict the API key to specific APIs and domains\n2. Regenerate the key if unrestricted\n3. Implement API key rotation policy\n4. Monitor API usage in Google Cloud Console"
    },
    "JWT Token": {
        "severity": "HIGH",
        "cvss": "8.1",
        "impact": "Session hijacking and authentication bypass. Attacker can impersonate users, access protected resources, and potentially escalate privileges if token contains admin claims.",
        "remediation": "1. Invalidate the token and force re-authentication\n2. Implement token rotation and short expiry times\n3. Use secure token storage (HttpOnly cookies)\n4. Validate all JWT claims on the server"
    },
    "Private Key": {
        "severity": "CRITICAL",
        "cvss": "9.8",
        "impact": "Complete cryptographic compromise. Can be used to decrypt data, sign malicious code, impersonate servers in TLS connections, or forge digital signatures.",
        "remediation": "1. Immediately revoke and regenerate the key pair\n2. Update all systems using the key\n3. Implement HSM for key storage\n4. Never commit private keys to version control"
    },
    "Database Connection String": {
        "severity": "CRITICAL",
        "cvss": "9.4",
        "impact": "Direct database access. Attacker can read, modify, or delete all database records. Can lead to complete data breach, data manipulation, or ransomware attacks.",
        "remediation": "1. Rotate database credentials immediately\n2. Restrict database access to specific IPs\n3. Use connection pooling with encrypted connections\n4. Implement database activity monitoring"
    },
    "MongoDB URI": {
        "severity": "CRITICAL",
        "cvss": "9.4",
        "impact": "Full MongoDB database access. Can export all collections, modify data, create admin users, or drop databases entirely.",
        "remediation": "1. Change MongoDB password and update connection strings\n2. Enable authentication and SCRAM\n3. Configure network access controls\n4. Enable MongoDB audit logging"
    },
    "Slack Webhook": {
        "severity": "MEDIUM",
        "cvss": "5.3",
        "impact": "Can send messages to Slack channels, potentially for phishing, social engineering, or spreading misinformation within the organization.",
        "remediation": "1. Regenerate the webhook URL in Slack\n2. Implement webhook secret validation\n3. Monitor channel for suspicious messages\n4. Use Slack's incoming webhook restrictions"
    },
    "Discord Webhook": {
        "severity": "MEDIUM",
        "cvss": "5.3",
        "impact": "Send arbitrary messages to Discord channels. Can be used for spam, phishing links, or reputation damage.",
        "remediation": "1. Delete and recreate the webhook\n2. Implement rate limiting on webhook usage\n3. Use bot tokens with proper permissions instead\n4. Monitor Discord server for abuse"
    },
    "Telegram Bot Token": {
        "severity": "HIGH",
        "cvss": "7.2",
        "impact": "Full control of Telegram bot. Can read all messages to the bot, send messages as the bot, and access user information who interacted with the bot.",
        "remediation": "1. Revoke token using @BotFather /revoke command\n2. Create a new token with /token command\n3. Update all applications using the bot\n4. Review bot's chat history for sensitive data"
    },
    "Twilio Auth Token": {
        "severity": "HIGH",
        "cvss": "8.1",
        "impact": "Access to SMS/Voice services. Attacker can send SMS as your account, make calls, access call logs, and incur significant charges.",
        "remediation": "1. Rotate auth token in Twilio Console\n2. Review usage logs for unauthorized activity\n3. Enable Twilio Shield for fraud protection\n4. Implement API key authentication instead"
    },
    "SendGrid API Key": {
        "severity": "HIGH",
        "cvss": "7.5",
        "impact": "Send emails from your domain. Can be used for phishing campaigns, reputation damage, or accessing email templates and contact lists.",
        "remediation": "1. Delete and recreate API key in SendGrid\n2. Review sent email history\n3. Use API keys with minimal permissions\n4. Enable IP access management"
    },
    "Mailchimp API Key": {
        "severity": "MEDIUM",
        "cvss": "6.5",
        "impact": "Access to email marketing campaigns, subscriber lists, and templates. Can expose customer PII and be used for targeted phishing.",
        "remediation": "1. Regenerate API key in Mailchimp account\n2. Export and review subscriber data access\n3. Limit API key permissions\n4. Enable two-factor authentication"
    },
    "Heroku API Key": {
        "severity": "HIGH",
        "cvss": "8.1",
        "impact": "Deploy code to Heroku apps, access environment variables (often containing other secrets), and modify application configurations.",
        "remediation": "1. Regenerate API key: heroku authorizations:revoke\n2. Review app activity and deployments\n3. Rotate all environment variables\n4. Enable Heroku Shield for sensitive apps"
    },
    "npm Token": {
        "severity": "CRITICAL",
        "cvss": "9.1",
        "impact": "Publish malicious packages, take over existing packages, or access private packages. Can lead to supply chain attacks affecting thousands of downstream users.",
        "remediation": "1. Revoke token: npm token revoke <token>\n2. Enable 2FA on npm account\n3. Use granular access tokens\n4. Enable npm audit in CI/CD"
    },
    "Basic Auth Credentials": {
        "severity": "HIGH",
        "cvss": "7.5",
        "impact": "Direct access to protected resources. Depending on the service, can lead to admin access, data exposure, or system compromise.",
        "remediation": "1. Change credentials immediately\n2. Implement proper authentication (OAuth, JWT)\n3. Use HTTPS to prevent credential interception\n4. Enable rate limiting and account lockout"
    },
    "API Endpoint": {
        "severity": "LOW",
        "cvss": "3.1",
        "impact": "Information disclosure of internal API structure. May reveal attack surface for further exploitation or hidden functionality.",
        "remediation": "1. Review endpoint security and authentication\n2. Implement API gateway with proper controls\n3. Use API versioning and deprecation\n4. Minimize exposed endpoints in client-side code"
    },
    "Admin Endpoint": {
        "severity": "MEDIUM",
        "cvss": "5.3",
        "impact": "Reveals administrative functionality. Can be targeted for authentication bypass or privilege escalation attacks.",
        "remediation": "1. Ensure strong authentication on admin endpoints\n2. Implement IP whitelisting for admin access\n3. Use separate admin domain/subdomain\n4. Enable detailed logging on admin actions"
    },
    "Internal URL": {
        "severity": "MEDIUM",
        "cvss": "5.0",
        "impact": "Exposes internal infrastructure details. Can be used for SSRF attacks or to map internal network architecture.",
        "remediation": "1. Remove internal URLs from client-side code\n2. Implement proper SSRF protections\n3. Use internal DNS that doesn't resolve externally\n4. Segment internal networks properly"
    },
    "GraphQL Endpoint": {
        "severity": "MEDIUM",
        "cvss": "5.3",
        "impact": "Reveals GraphQL API. Can be used for introspection attacks to map all available queries and mutations, potentially finding sensitive operations.",
        "remediation": "1. Disable introspection in production\n2. Implement query depth limiting\n3. Use persisted queries for sensitive operations\n4. Add proper authentication to all resolvers"
    },
    "Generic Secret": {
        "severity": "MEDIUM",
        "cvss": "6.5",
        "impact": "Potential access to protected resources. Impact depends on the specific service or resource the secret protects.",
        "remediation": "1. Identify the service using this secret\n2. Rotate the credential\n3. Implement secrets management\n4. Add secret scanning to CI/CD pipeline"
    },
    "Password": {
        "severity": "HIGH",
        "cvss": "7.5",
        "impact": "Direct credential exposure. Can be used for unauthorized access, credential stuffing attacks on other services, or privilege escalation.",
        "remediation": "1. Force password reset for affected accounts\n2. Check for password reuse across services\n3. Implement password policies and MFA\n4. Use password managers and hashing"
    },
}


def get_impact_info(pattern_name: str) -> Dict:
    """Get impact information for a finding type"""
    # Try exact match first
    if pattern_name in IMPACT_DATABASE:
        return IMPACT_DATABASE[pattern_name]
    
    # Try partial match
    for key in IMPACT_DATABASE:
        if key.lower() in pattern_name.lower() or pattern_name.lower() in key.lower():
            return IMPACT_DATABASE[key]
    
    # Default impact for unknown types
    return {
        "severity": "MEDIUM",
        "cvss": "5.0",
        "impact": "Potential information disclosure or unauthorized access. The exposed secret may provide access to protected resources or sensitive functionality.",
        "remediation": "1. Identify the purpose of this credential\n2. Rotate or revoke the secret immediately\n3. Review access logs for unauthorized usage\n4. Implement proper secrets management"
    }


class HtmlReportGenerator:
    """Generate professional HTML reports in multiple formats"""
    
    def __init__(self, config: ReportConfig):
        self.config = config
        self.timestamp = datetime.now()
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color for severity level"""
        colors = {
            "CRITICAL": "#DC2626",
            "HIGH": "#EA580C",
            "MEDIUM": "#CA8A04",
            "LOW": "#16A34A",
            "INFO": "#2563EB"
        }
        return colors.get(severity.upper(), "#6B7280")
    
    def _get_severity_badge(self, severity: str) -> str:
        """Generate severity badge HTML"""
        color = self._get_severity_color(severity)
        return f'<span class="severity-badge" style="background-color: {color};">{severity}</span>'
    
    def _escape(self, text: str) -> str:
        """Escape HTML characters"""
        return html.escape(str(text))
    
    def _generate_base_css(self) -> str:
        """Generate base CSS styles"""
        return """
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #0f0f23 0%, #1a1a3e 100%);
                color: #e0e0e0;
                min-height: 100vh;
                line-height: 1.6;
            }
            
            .container {
                max-width: 1200px;
                margin: 0 auto;
                padding: 40px 20px;
            }
            
            /* Header Styles */
            .report-header {
                background: linear-gradient(135deg, #1e3a5f 0%, #0d1f3c 100%);
                border-radius: 16px;
                padding: 40px;
                margin-bottom: 30px;
                border: 1px solid #2563eb33;
                box-shadow: 0 20px 40px rgba(0,0,0,0.3);
            }
            
            .report-title {
                font-size: 2.5rem;
                font-weight: 700;
                background: linear-gradient(90deg, #00ff88, #00d4ff);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                margin-bottom: 10px;
            }
            
            .report-subtitle {
                color: #94a3b8;
                font-size: 1.1rem;
            }
            
            .meta-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin-top: 30px;
            }
            
            .meta-item {
                background: rgba(255,255,255,0.05);
                padding: 15px 20px;
                border-radius: 10px;
                border: 1px solid rgba(255,255,255,0.1);
            }
            
            .meta-label {
                color: #64748b;
                font-size: 0.85rem;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            
            .meta-value {
                color: #f1f5f9;
                font-size: 1.1rem;
                font-weight: 600;
                margin-top: 5px;
            }
            
            /* Stats Cards */
            .stats-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }
            
            .stat-card {
                background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
                border-radius: 12px;
                padding: 25px;
                text-align: center;
                border: 1px solid rgba(255,255,255,0.1);
                transition: transform 0.3s, box-shadow 0.3s;
            }
            
            .stat-card:hover {
                transform: translateY(-5px);
                box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            }
            
            .stat-number {
                font-size: 2.5rem;
                font-weight: 700;
                margin-bottom: 5px;
            }
            
            .stat-label {
                color: #94a3b8;
                font-size: 0.9rem;
            }
            
            .critical { color: #DC2626; }
            .high { color: #EA580C; }
            .medium { color: #CA8A04; }
            .low { color: #16A34A; }
            
            /* Finding Cards */
            .finding-card {
                background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
                border-radius: 16px;
                margin-bottom: 25px;
                overflow: hidden;
                border: 1px solid rgba(255,255,255,0.1);
                box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            }
            
            .finding-header {
                padding: 25px 30px;
                border-bottom: 1px solid rgba(255,255,255,0.1);
                display: flex;
                justify-content: space-between;
                align-items: center;
                flex-wrap: wrap;
                gap: 15px;
            }
            
            .finding-title {
                font-size: 1.3rem;
                font-weight: 600;
                color: #f1f5f9;
            }
            
            .severity-badge {
                padding: 6px 16px;
                border-radius: 20px;
                font-size: 0.85rem;
                font-weight: 600;
                color: white;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            
            .finding-body {
                padding: 30px;
            }
            
            .finding-section {
                margin-bottom: 25px;
            }
            
            .finding-section:last-child {
                margin-bottom: 0;
            }
            
            .section-title {
                color: #00d4ff;
                font-size: 1rem;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 1px;
                margin-bottom: 12px;
                display: flex;
                align-items: center;
                gap: 8px;
            }
            
            .section-title::before {
                content: '';
                width: 4px;
                height: 20px;
                background: linear-gradient(180deg, #00ff88, #00d4ff);
                border-radius: 2px;
            }
            
            .section-content {
                color: #cbd5e1;
                background: rgba(0,0,0,0.2);
                padding: 15px 20px;
                border-radius: 10px;
                border-left: 3px solid #00d4ff;
            }
            
            .code-block {
                background: #0d1117;
                border-radius: 8px;
                padding: 15px 20px;
                font-family: 'Fira Code', 'Consolas', monospace;
                font-size: 0.9rem;
                color: #00ff88;
                overflow-x: auto;
                border: 1px solid #30363d;
            }
            
            .url-display {
                word-break: break-all;
                color: #60a5fa;
            }
            
            .steps-list {
                list-style: none;
                counter-reset: step-counter;
            }
            
            .steps-list li {
                counter-increment: step-counter;
                padding: 12px 0;
                padding-left: 45px;
                position: relative;
                border-bottom: 1px solid rgba(255,255,255,0.05);
            }
            
            .steps-list li:last-child {
                border-bottom: none;
            }
            
            .steps-list li::before {
                content: counter(step-counter);
                position: absolute;
                left: 0;
                top: 12px;
                width: 28px;
                height: 28px;
                background: linear-gradient(135deg, #00ff88, #00d4ff);
                color: #0f0f23;
                font-weight: 700;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 0.85rem;
            }
            
            /* CVSS Score */
            .cvss-container {
                display: inline-flex;
                align-items: center;
                gap: 10px;
                background: rgba(0,0,0,0.3);
                padding: 8px 15px;
                border-radius: 8px;
                margin-top: 10px;
            }
            
            .cvss-score {
                font-size: 1.5rem;
                font-weight: 700;
            }
            
            .cvss-label {
                color: #94a3b8;
                font-size: 0.85rem;
            }
            
            /* Footer */
            .report-footer {
                text-align: center;
                padding: 40px;
                margin-top: 40px;
                border-top: 1px solid rgba(255,255,255,0.1);
                color: #64748b;
            }
            
            .footer-brand {
                font-size: 1.2rem;
                font-weight: 600;
                background: linear-gradient(90deg, #00ff88, #00d4ff);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                margin-bottom: 10px;
            }
            
            /* HackerOne Specific */
            .h1-header {
                background: linear-gradient(135deg, #8B5CF6 0%, #6B21A8 100%);
            }
            
            /* BugCrowd Specific */
            .bc-header {
                background: linear-gradient(135deg, #EA580C 0%, #C2410C 100%);
            }
            
            /* Email Specific */
            .email-header {
                background: linear-gradient(135deg, #0EA5E9 0%, #0369A1 100%);
            }
            
            /* Table Styles */
            .info-table {
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
            }
            
            .info-table th,
            .info-table td {
                padding: 12px 15px;
                text-align: left;
                border-bottom: 1px solid rgba(255,255,255,0.1);
            }
            
            .info-table th {
                color: #94a3b8;
                font-weight: 600;
                width: 180px;
            }
            
            .info-table td {
                color: #e0e0e0;
            }
            
            /* Print Styles */
            @media print {
                body {
                    background: white;
                    color: #1f2937;
                }
                
                .finding-card,
                .report-header,
                .stat-card {
                    background: white;
                    border: 1px solid #e5e7eb;
                    box-shadow: none;
                }
                
                .report-title,
                .footer-brand {
                    background: none;
                    -webkit-text-fill-color: #1f2937;
                    color: #1f2937;
                }
                
                .section-title {
                    color: #1f2937;
                }
            }
            
            @media (max-width: 768px) {
                .report-title {
                    font-size: 1.8rem;
                }
                
                .finding-header {
                    flex-direction: column;
                    align-items: flex-start;
                }
                
                .meta-grid {
                    grid-template-columns: 1fr;
                }
            }
        </style>
        """
    
    def generate_hackerone_report(self, findings: List, scan_result) -> str:
        """Generate HackerOne-style vulnerability report"""
        
        # Count findings by severity
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = f.severity() if hasattr(f, 'severity') else "MEDIUM"
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {self._escape(scan_result.target)}</title>
    {self._generate_base_css()}
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="report-header h1-header">
            <div class="report-title">🔒 Security Assessment Report</div>
            <div class="report-subtitle">HackerOne Format - Confidential Vulnerability Disclosure</div>
            
            <div class="meta-grid">
                <div class="meta-item">
                    <div class="meta-label">Target</div>
                    <div class="meta-value">{self._escape(scan_result.target)}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Program</div>
                    <div class="meta-value">{self._escape(self.config.program_name or 'Bug Bounty Program')}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Reporter</div>
                    <div class="meta-value">{self._escape(self.config.reporter_name)}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Date</div>
                    <div class="meta-value">{self.timestamp.strftime('%B %d, %Y')}</div>
                </div>
            </div>
        </div>
        
        <!-- Stats -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number critical">{severity_counts['CRITICAL']}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="stat-number high">{severity_counts['HIGH']}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card">
                <div class="stat-number medium">{severity_counts['MEDIUM']}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card">
                <div class="stat-number low">{severity_counts['LOW']}</div>
                <div class="stat-label">Low</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color: #00d4ff;">{scan_result.total_js_files}</div>
                <div class="stat-label">JS Files Scanned</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color: #00ff88;">{len(findings)}</div>
                <div class="stat-label">Total Findings</div>
            </div>
        </div>
        
        <!-- Findings -->
        <h2 style="color: #f1f5f9; margin-bottom: 25px; font-size: 1.8rem;">📋 Vulnerability Findings</h2>
"""
        
        # Generate each finding
        for idx, finding in enumerate(findings, 1):
            impact_info = get_impact_info(finding.pattern_name)
            severity = finding.severity() if hasattr(finding, 'severity') else impact_info['severity']
            
            html_content += f"""
        <div class="finding-card">
            <div class="finding-header">
                <div class="finding-title">#{idx}: {self._escape(finding.pattern_name)} Exposure</div>
                {self._get_severity_badge(severity)}
            </div>
            <div class="finding-body">
                <!-- Summary -->
                <div class="finding-section">
                    <div class="section-title">Executive Summary</div>
                    <div class="section-content">
                        A <strong>{severity}</strong> severity {self._escape(finding.pattern_name)} was discovered in the JavaScript source code at <code>{self._escape(finding.url[:80])}</code>. This exposure could allow an attacker to gain unauthorized access to protected resources.
                    </div>
                </div>
                
                <!-- Technical Details -->
                <div class="finding-section">
                    <div class="section-title">Vulnerability Details</div>
                    <table class="info-table">
                        <tr>
                            <th>Vulnerability Type</th>
                            <td>Sensitive Data Exposure - {self._escape(finding.category)}</td>
                        </tr>
                        <tr>
                            <th>Pattern Matched</th>
                            <td>{self._escape(finding.pattern_name)}</td>
                        </tr>
                        <tr>
                            <th>Confidence</th>
                            <td>{finding.confidence}%</td>
                        </tr>
                        <tr>
                            <th>Affected URL</th>
                            <td class="url-display">{self._escape(finding.url)}</td>
                        </tr>
                        {"<tr><th>Line Number</th><td>" + str(finding.line_number) + "</td></tr>" if finding.line_number else ""}
                    </table>
                    
                    <div class="cvss-container">
                        <span class="cvss-score" style="color: {self._get_severity_color(severity)};">{impact_info['cvss']}</span>
                        <span class="cvss-label">CVSS Score</span>
                    </div>
                </div>
                
                <!-- Proof of Concept -->
                <div class="finding-section">
                    <div class="section-title">Proof of Concept</div>
                    <p style="margin-bottom: 10px; color: #94a3b8;">Secret Value Found:</p>
                    <div class="code-block">{self._escape(finding.matched_value)}</div>
                    {f'<p style="margin-top: 15px; color: #94a3b8;">Context:</p><div class="code-block">{self._escape(finding.context)}</div>' if finding.context else ''}
                </div>
                
                <!-- Steps to Reproduce -->
                <div class="finding-section">
                    <div class="section-title">Steps to Reproduce</div>
                    <ol class="steps-list">
                        <li>Navigate to the target URL: <code>{self._escape(finding.url)}</code></li>
                        <li>Open browser developer tools (F12) and go to the Sources tab</li>
                        <li>Search for the exposed secret using Ctrl+F</li>
                        <li>Locate the secret at {f"line {finding.line_number}" if finding.line_number else "the matched location"}</li>
                        <li>Observe the exposed {self._escape(finding.pattern_name)} in the JavaScript source</li>
                    </ol>
                </div>
                
                <!-- Impact -->
                <div class="finding-section">
                    <div class="section-title">Impact</div>
                    <div class="section-content">
                        {self._escape(impact_info['impact'])}
                    </div>
                </div>
                
                <!-- Remediation -->
                <div class="finding-section">
                    <div class="section-title">Recommended Fix</div>
                    <div class="section-content">
                        <pre style="white-space: pre-wrap; font-family: inherit;">{self._escape(impact_info['remediation'])}</pre>
                    </div>
                </div>
            </div>
        </div>
"""
        
        # Footer
        html_content += f"""
        <!-- Footer -->
        <div class="report-footer">
            <div class="footer-brand">🦇 NightCrawler v2.5</div>
            <p>Generated by {self._escape(self.config.reporter_name)} | {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p style="margin-top: 10px;">Keep Learning // Keep Hacking</p>
        </div>
    </div>
</body>
</html>
"""
        return html_content
    
    def generate_bugcrowd_report(self, findings: List, scan_result) -> str:
        """Generate BugCrowd-style vulnerability report"""
        
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = f.severity() if hasattr(f, 'severity') else "MEDIUM"
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BugCrowd Submission Report - {self._escape(scan_result.target)}</title>
    {self._generate_base_css()}
</head>
<body>
    <div class="container">
        <div class="report-header bc-header">
            <div class="report-title">🐛 BugCrowd Vulnerability Report</div>
            <div class="report-subtitle">Vulnerability Reward Program Submission</div>
            
            <div class="meta-grid">
                <div class="meta-item">
                    <div class="meta-label">Asset</div>
                    <div class="meta-value">{self._escape(scan_result.target)}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Program</div>
                    <div class="meta-value">{self._escape(self.config.program_name or 'VRP Submission')}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Researcher</div>
                    <div class="meta-value">{self._escape(self.config.reporter_name)}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Submission Date</div>
                    <div class="meta-value">{self.timestamp.strftime('%B %d, %Y')}</div>
                </div>
            </div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number critical">{severity_counts['CRITICAL']}</div>
                <div class="stat-label">P1 - Critical</div>
            </div>
            <div class="stat-card">
                <div class="stat-number high">{severity_counts['HIGH']}</div>
                <div class="stat-label">P2 - High</div>
            </div>
            <div class="stat-card">
                <div class="stat-number medium">{severity_counts['MEDIUM']}</div>
                <div class="stat-label">P3 - Medium</div>
            </div>
            <div class="stat-card">
                <div class="stat-number low">{severity_counts['LOW']}</div>
                <div class="stat-label">P4 - Low</div>
            </div>
        </div>
        
        <h2 style="color: #f1f5f9; margin-bottom: 25px; font-size: 1.8rem;">📊 Discovered Vulnerabilities</h2>
"""
        
        for idx, finding in enumerate(findings, 1):
            impact_info = get_impact_info(finding.pattern_name)
            severity = finding.severity() if hasattr(finding, 'severity') else impact_info['severity']
            priority = {"CRITICAL": "P1", "HIGH": "P2", "MEDIUM": "P3", "LOW": "P4"}.get(severity, "P3")
            
            html_content += f"""
        <div class="finding-card">
            <div class="finding-header">
                <div class="finding-title">[{priority}] {self._escape(finding.pattern_name)} in JavaScript Source</div>
                {self._get_severity_badge(severity)}
            </div>
            <div class="finding-body">
                <div class="finding-section">
                    <div class="section-title">Overview</div>
                    <div class="section-content">
                        A {self._escape(finding.pattern_name)} was discovered exposed in client-side JavaScript, potentially allowing unauthorized access to sensitive resources. The vulnerability was found in {self._escape(finding.category)} category with {finding.confidence}% confidence.
                    </div>
                </div>
                
                <div class="finding-section">
                    <div class="section-title">Technical Details</div>
                    <table class="info-table">
                        <tr><th>VRT Category</th><td>Server Security Misconfiguration > Sensitive Data Exposure</td></tr>
                        <tr><th>Location</th><td class="url-display">{self._escape(finding.url)}</td></tr>
                        <tr><th>Secret Type</th><td>{self._escape(finding.pattern_name)}</td></tr>
                        <tr><th>CVSS</th><td>{impact_info['cvss']}</td></tr>
                    </table>
                </div>
                
                <div class="finding-section">
                    <div class="section-title">Proof of Concept</div>
                    <div class="code-block">{self._escape(finding.matched_value)}</div>
                </div>
                
                <div class="finding-section">
                    <div class="section-title">Business Impact</div>
                    <div class="section-content">{self._escape(impact_info['impact'])}</div>
                </div>
                
                <div class="finding-section">
                    <div class="section-title">Mitigation Steps</div>
                    <div class="section-content">
                        <pre style="white-space: pre-wrap; font-family: inherit;">{self._escape(impact_info['remediation'])}</pre>
                    </div>
                </div>
            </div>
        </div>
"""
        
        html_content += f"""
        <div class="report-footer">
            <div class="footer-brand">🦇 NightCrawler v2.5</div>
            <p>Submitted by {self._escape(self.config.reporter_name)}</p>
            <p style="margin-top: 10px;">Keep Learning // Keep Hacking</p>
        </div>
    </div>
</body>
</html>
"""
        return html_content
    
    def generate_email_report(self, findings: List, scan_result) -> str:
        """Generate Email-friendly HTML report"""
        
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = f.severity() if hasattr(f, 'severity') else "MEDIUM"
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {self._escape(scan_result.target)}</title>
    {self._generate_base_css()}
</head>
<body>
    <div class="container">
        <div class="report-header email-header">
            <div class="report-title">📧 Security Scan Report</div>
            <div class="report-subtitle">Automated JavaScript Secret Analysis</div>
            
            <div class="meta-grid">
                <div class="meta-item">
                    <div class="meta-label">To</div>
                    <div class="meta-value">Security Team</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">From</div>
                    <div class="meta-value">{self._escape(self.config.reporter_name)}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Subject</div>
                    <div class="meta-value">JS Secret Scan: {self._escape(scan_result.target)}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Date</div>
                    <div class="meta-value">{self.timestamp.strftime('%B %d, %Y %H:%M')}</div>
                </div>
            </div>
        </div>
        
        <!-- Quick Summary -->
        <div class="finding-card">
            <div class="finding-header">
                <div class="finding-title">📊 Executive Summary</div>
            </div>
            <div class="finding-body">
                <p style="margin-bottom: 20px;">
                    NightCrawler completed a security scan of <strong>{self._escape(scan_result.target)}</strong>. 
                    The scan analyzed <strong>{scan_result.total_js_files}</strong> JavaScript files and discovered 
                    <strong>{len(findings)}</strong> potential secrets exposed in client-side code.
                </p>
                
                <table class="info-table">
                    <tr><th>URLs Scanned</th><td>{scan_result.total_urls_scanned}</td></tr>
                    <tr><th>JS Files Analyzed</th><td>{scan_result.total_js_files}</td></tr>
                    <tr><th>Subdomains Found</th><td>{scan_result.subdomains_found}</td></tr>
                    <tr><th>Scan Duration</th><td>{scan_result.scan_time:.2f} seconds</td></tr>
                </table>
                
                <div class="stats-grid" style="margin-top: 20px;">
                    <div class="stat-card"><div class="stat-number critical">{severity_counts['CRITICAL']}</div><div class="stat-label">Critical</div></div>
                    <div class="stat-card"><div class="stat-number high">{severity_counts['HIGH']}</div><div class="stat-label">High</div></div>
                    <div class="stat-card"><div class="stat-number medium">{severity_counts['MEDIUM']}</div><div class="stat-label">Medium</div></div>
                    <div class="stat-card"><div class="stat-number low">{severity_counts['LOW']}</div><div class="stat-label">Low</div></div>
                </div>
            </div>
        </div>
        
        <h2 style="color: #f1f5f9; margin-bottom: 25px; font-size: 1.5rem;">🔍 Detailed Findings</h2>
"""
        
        for idx, finding in enumerate(findings, 1):
            impact_info = get_impact_info(finding.pattern_name)
            severity = finding.severity() if hasattr(finding, 'severity') else impact_info['severity']
            
            html_content += f"""
        <div class="finding-card">
            <div class="finding-header">
                <div class="finding-title">#{idx} - {self._escape(finding.pattern_name)}</div>
                {self._get_severity_badge(severity)}
            </div>
            <div class="finding-body">
                <table class="info-table">
                    <tr><th>Type</th><td>{self._escape(finding.category)} - {self._escape(finding.pattern_name)}</td></tr>
                    <tr><th>Location</th><td class="url-display">{self._escape(finding.url)}</td></tr>
                    <tr><th>Confidence</th><td>{finding.confidence}%</td></tr>
                    <tr><th>CVSS</th><td>{impact_info['cvss']}</td></tr>
                </table>
                
                <div class="finding-section" style="margin-top: 20px;">
                    <div class="section-title">Exposed Value</div>
                    <div class="code-block">{self._escape(finding.matched_value)}</div>
                </div>
                
                <div class="finding-section">
                    <div class="section-title">Impact</div>
                    <div class="section-content">{self._escape(impact_info['impact'][:300])}...</div>
                </div>
            </div>
        </div>
"""
        
        html_content += f"""
        <div class="report-footer">
            <div class="footer-brand">🦇 NightCrawler v2.5</div>
            <p>Automated Security Scanner by {self._escape(self.config.reporter_name)}</p>
            <p style="margin-top: 10px;">Keep Learning // Keep Hacking</p>
        </div>
    </div>
</body>
</html>
"""
        return html_content
    
    def generate(self, findings: List, scan_result, output_path: str) -> str:
        """Generate report based on configured template"""
        
        if self.config.template == "hackerone":
            content = self.generate_hackerone_report(findings, scan_result)
        elif self.config.template == "bugcrowd":
            content = self.generate_bugcrowd_report(findings, scan_result)
        elif self.config.template == "email":
            content = self.generate_email_report(findings, scan_result)
        else:
            content = self.generate_hackerone_report(findings, scan_result)
        
        # Save to file
        output_file = Path(output_path)
        output_file.write_text(content, encoding='utf-8')
        
        return output_path
