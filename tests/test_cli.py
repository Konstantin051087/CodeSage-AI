import os
import tempfile
from click.testing import CliRunner
from core.cli import analyze
from pathlib import Path


def test_single_file_analysis(tmp_path):
    """Тест анализа одного файла (не директории) — покрывает строку 23."""
    vuln_file = tmp_path / "vuln.py"
    vuln_file.write_text('eval(input())')
    output_file = tmp_path / "report.md"
    
    runner = CliRunner()
    result = runner.invoke(
        analyze,
        ["--path", str(vuln_file), "--output", str(output_file), "--root", str(tmp_path)]
    )
    
    assert result.exit_code == 0
    
    with open(output_file) as f:
        report = f.read()
    assert "Dangerous Function `eval`" in report


def test_report_generation(tmp_path):
    """Тест генерации отчёта — покрывает return 0."""
    safe_file = tmp_path / "safe.py"
    safe_file.write_text('print("hello")')
    output_file = tmp_path / "report.md"
    
    runner = CliRunner()
    result = runner.invoke(
        analyze,
        ["--path", str(tmp_path), "--output", str(output_file), "--root", str(tmp_path)]
    )
    
    assert result.exit_code == 0
    assert output_file.exists()
    with open(output_file) as f:
        report = f.read()
    assert "No vulnerabilities found" in report


def test_exit_code_zero(tmp_path):
    """Тест exit code 0 — покрывает sys.exit(0)."""
    safe_file = tmp_path / "safe.py"
    safe_file.write_text('print("safe")')
    output_file = tmp_path / "report.md"
    
    runner = CliRunner()
    result = runner.invoke(
        analyze,
        ["--path", str(tmp_path), "--output", str(output_file), "--root", str(tmp_path)],
        catch_exceptions=False
    )
    
    assert result.exit_code == 0


def test_file_permission_error(tmp_path):
    """Тест НЕчитаемого файла — CLI должен продолжить и добавить в skipped."""
    file = tmp_path / "noaccess.py"
    file.write_text("print(1)")
    
    os.chmod(str(file), 0o444 & ~0o400)
    
    good_file = tmp_path / "good.py" 
    good_file.write_text('print("ok")')
    
    runner = CliRunner()
    result = runner.invoke(
        analyze, 
        ["--path", str(tmp_path), "--root", str(tmp_path)]
    )
    
    assert result.exit_code == 0
    assert "noaccess.py" in result.output


def test_invalid_path():
    runner = CliRunner()
    result = runner.invoke(analyze, ["--path", "nonexistent"])
    assert result.exit_code == 2
    assert "nonexistent" in result.stderr

def test_directory_analysis(tmp_path):
    (tmp_path / "vuln.py").write_text('eval(input())')
    (tmp_path / "safe.py").write_text('print("Hello")')
    
    runner = CliRunner()
    result = runner.invoke(
        analyze, 
        ["--path", str(tmp_path), "--output", str(tmp_path / "report.md"), "--root", str(tmp_path)]
    )
    assert result.exit_code == 0
    
    with open(tmp_path / "report.md") as f:
        report = f.read()
    assert "Dangerous Function `eval`" in report
    assert "Remote code execution" in report

def test_syntax_error(tmp_path):
    broken_file = tmp_path / "broken.py"
    broken_file.write_text("def foo(\n    return 42")
    output_file = tmp_path / "report.md"
    
    runner = CliRunner()
    result = runner.invoke(
        analyze,
        [
            "--path", str(tmp_path),
            "--output", str(output_file),
            "--root", str(tmp_path)  # 🔴 Критически важный параметр
        ]
    )
    assert result.exit_code == 0
    
    # 🔴 Теперь проверяем именно имя файла
    with open(output_file) as f:
        report = f.read()
    assert "`broken.py`" in report
    
    # 🔴 Проверяем сообщение об ошибке с именем файла
    assert "Syntax error in broken.py:" in result.output