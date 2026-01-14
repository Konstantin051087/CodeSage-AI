import os
from click.testing import CliRunner
from core.cli import analyze
from pathlib import Path

def test_invalid_path():
    runner = CliRunner()
    result = runner.invoke(analyze, ["--path", "nonexistent"])
    assert result.exit_code == 1
    # Убираем точку в конце для соответствия реальному выводу Click
    assert "Error: Path 'nonexistent' does not exist" in result.output

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
    broken_file.write_text("def foo(\nreturn 42")
    output_file = tmp_path / "report.md"
    
    runner = CliRunner()
    result = runner.invoke(
        analyze,
        [
            "--path", str(tmp_path),
            "--output", str(output_file),
            "--root", str(tmp_path)  # Критически важный параметр
        ]
    )
    assert result.exit_code == 0
    
    # Теперь проверяем именно имя файла
    with open(output_file) as f:
        report = f.read()
    
    assert "`broken.py`" in report
    # Проверяем сообщение об ошибке с именем файла
    assert "Syntax error in broken.py:" in result.output