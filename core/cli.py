# Файл: core/cli.py (обновленная версия)
import click
import libcst as cst
from .detectors import SQLInjectionDetector, DangerousFunctionDetector
from .reporter import generate_markdown_report
import os
from pathlib import Path

@click.command()
@click.option("--path", required=True, help="Path to Python file or directory")
@click.option("--output", default="report.md", help="Output report file")
@click.option("--root", default=".", help="Root directory for relative paths (default: current directory)")
@click.option("--no-ai", is_flag=True, help="Disable AI explanations (faster, less context)")
@click.option("--ai-model", default=None, help="Path to custom AI model (optional)")
def analyze(path, output, root, no_ai, ai_model):
    """
    Анализирует Python-код на уязвимости и генерирует отчет
    
    Args:
        path: Путь к файлу или директории
        output: Имя файла для отчета
        root: Корневая директория для относительных путей
        no_ai: Отключить ИИ-объяснения
        ai_model: Путь к кастомной модели ИИ
    """
    if not os.path.exists(path):
        click.echo(f"Error: Path '{path}' does not exist.", err=True)
        return 1
    
    # Определяем корневую директорию для относительных путей
    root_path = Path(root).resolve()
    vulnerabilities = []
    skipped_files = []
    
    use_ai = not no_ai
    
    if os.path.isfile(path):
        files = [path]
    else:
        files = [
            os.path.join(root_dir, f)
            for root_dir, _, files in os.walk(path)
            for f in files
            if f.endswith(".py")
        ]
    
    for file_path in files:
        try:
            with open(file_path, "r") as f:
                code = f.read()
            
            # Получаем относительный путь от корневой директории
            rel_path = os.path.relpath(Path(file_path).resolve(), root_path)
            module = cst.parse_module(code)
            wrapper = cst.MetadataWrapper(module)
            
            # Запуск детекторов
            sql_detector = SQLInjectionDetector()
            dangerous_detector = DangerousFunctionDetector()
            wrapper.visit(sql_detector)
            wrapper.visit(dangerous_detector)
            
            # Добавление пути к уязвимостям
            for vuln in sql_detector.vulnerabilities + dangerous_detector.vulnerabilities:
                vuln["file"] = rel_path
            
            vulnerabilities.extend(sql_detector.vulnerabilities)
            vulnerabilities.extend(dangerous_detector.vulnerabilities)
            
        except cst.ParserSyntaxError as e:
            # Используем rel_path вместо file_path
            rel_file = os.path.relpath(Path(file_path).resolve(), root_path)
            click.echo(f"Syntax error in {rel_file}: {str(e)}", err=True)
            skipped_files.append(rel_file)
    
    # Генерация отчета с настройками ИИ
    report = generate_markdown_report(vulnerabilities, skipped_files, use_ai=use_ai)
    with open(output, "w") as f:
        f.write(report)
    
    click.echo(f"✅ Report saved to {output}")
    
    # Выводим информацию об использовании ИИ
    if use_ai:
        click.echo("🤖 AI explanations generated for business impact analysis")
    
    return 0

if __name__ == "__main__":
    exit_code = analyze()
    exit(exit_code)