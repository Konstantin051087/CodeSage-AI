from core.reporter import generate_markdown_report

def test_skipped_files_report():
    report = generate_markdown_report([], skipped_files=["broken.py"])
    assert "⚠️ **Skipped files due to syntax errors**:" in report
    assert "- `broken.py`" in report
    assert "No vulnerabilities found" not in report  # Даже при отсутствии уязвимостей

def test_sql_report():
    vuln = {
        "type": "sql_injection",
        "line": 5,
        "code": 'cursor.execute(f"SELECT {user}")',
        "file": "app.py",
        "fix": "# Use parameterized queries"
    }
    report = generate_markdown_report([vuln])
    assert "**Business Impact**: Risk of full database leak" in report
    assert "GDPR fines up to €20M" in report

def test_dangerous_function_report():
    vuln = {
        "type": "dangerous_function",
        "function": "pickle.loads",
        "line": 10,
        "file": "utils.py",
        "fix": "Avoid pickle.loads() — use json.loads"
    }
    report = generate_markdown_report([vuln])
    assert "Remote code execution → server takeover" in report
    assert "use json.loads" in report

def test_empty_report():
    report = generate_markdown_report([])
    assert "✅ **CodeSage Report**: No vulnerabilities found." in report

def test_skipped_files_report():
    report = generate_markdown_report([], skipped_files=["broken.py"])
    assert "⚠️ **Skipped files due to syntax errors**:" in report
    assert "- `broken.py`" in report
    assert "No vulnerabilities found" not in report