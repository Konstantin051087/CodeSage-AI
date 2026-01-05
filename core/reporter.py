def generate_markdown_report(vulnerabilities: list) -> str:
    if not vulnerabilities:
        return "✅ **CodeSage Report**: No vulnerabilities found."
    
    report = "⚠️ **CodeSage Security Report**\n\n"
    for vuln in vulnerabilities:
        vuln_type = vuln.get("type", "unknown")
        line = vuln.get("line", "N/A")
        file = vuln.get("file", "unknown")
        
        if vuln_type == "sql_injection":
            code = vuln.get("code", "N/A")
            fix = vuln.get("fix", "No suggested fix available.")
            report += (
                f"### 🔥 SQL Injection (Line {line})\n"
                f"**File**: `{file}`\n"
                f"**Code**:\n```python\n{code}\n```\n"
                f"**Fix**:\n```python\n{fix}\n```\n"
                "**Business Impact**: Risk of full database leak → GDPR fines up to €20M.\n\n"
            )
        elif vuln_type == "dangerous_function":
            function = vuln.get("function", "unknown")
            fix = vuln.get("fix", "Avoid using this dangerous function. Prefer safer alternatives.")
            report += (
                f"### ⚡ Dangerous Function `{function}` (Line {line})\n"
                f"**Fix**: {fix}\n"
                "**Business Impact**: Remote code execution → server takeover.\n\n"
            )
    return report
