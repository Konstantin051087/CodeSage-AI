def generate_markdown_report(vulnerabilities: list) -> str:
    if not vulnerabilities:
        return "✅ **CodeSage Report**: No vulnerabilities found."
    
    report = "⚠️ **CodeSage Security Report**\n\n"
    for vuln in vulnerabilities:
        if vuln["type"] == "sql_injection":
            report += (
                f"### 🔥 SQL Injection (Line {vuln['line']})\n"
                f"**File**: `{vuln['file']}`\n"
                f"**Code**:\n```python\n{vuln['code']}\n```\n"
                f"**Fix**:\n```python\n{vuln['fix']}\n```\n"
                "**Business Impact**: Risk of full database leak → GDPR fines up to €20M.\n\n"
            )
        elif vuln["type"] == "dangerous_function":
            report += (
                f"### ⚡ Dangerous Function `{vuln['function']}` (Line {vuln['line']})\n"
                f"**Fix**: {vuln['fix']}\n"
                "**Business Impact**: Remote code execution → server takeover.\n\n"
            )
    return report