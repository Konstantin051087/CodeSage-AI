def generate_markdown_report(vulnerabilities: list, skipped_files: list = None) -> str:
    if skipped_files is None:
        skipped_files = []
    
    report_lines = []
    
    # 🔴 Добавлен блок для пропущенных файлов
    if skipped_files:
        report_lines.append("⚠️ **Skipped files due to syntax errors**:\n")
        for file in skipped_files:
            report_lines.append(f"- `{file}`")
        report_lines.append("\n")
    
    # Основной отчет по уязвимостям
    if not vulnerabilities:
        if not skipped_files:  # Только если нет пропущенных файлов
            report_lines.append("✅ **CodeSage Report**: No vulnerabilities found.")
    else:
        report_lines.append("⚠️ **CodeSage Security Report**\n")
        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "unknown")
            line = vuln.get("line", "N/A")
            file = vuln.get("file", "unknown")
            
            if vuln_type == "sql_injection":
                code = vuln.get("code", "N/A")
                fix = vuln.get("fix", "No suggested fix available.")
                report_lines.append(
                    f"### 🔥 SQL Injection (Line {line})\n"
                    f"**File**: `{file}`\n"
                    f"**Code**:\n```python\n{code}\n```\n"
                    f"**Fix**:\n```python\n{fix}\n```\n"
                    "**Business Impact**: Risk of full database leak → GDPR fines up to €20M.\n\n"
                )
            elif vuln_type == "dangerous_function":
                function = vuln.get("function", "unknown")
                fix = vuln.get("fix", "Avoid using this dangerous function. Prefer safer alternatives.")
                report_lines.append(
                    f"### ⚡ Dangerous Function `{function}` (Line {line})\n"
                    f"**Fix**: {fix}\n"
                    "**Business Impact**: Remote code execution → server takeover.\n\n"
                )
    
    return "\n".join(report_lines)