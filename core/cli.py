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
@click.pass_context  # Критически важный декоратор для доступа к контексту
def analyze(ctx, path, output, root):
    if not os.path.exists(path):
        # Правильная обработка ошибки в Click
        click.echo(f"Error: Path '{path}' does not exist.", err=True)
        ctx.exit(1)  # Это гарантирует код выхода 1
    
    # Определяем корневую директорию для относительных путей
    root_path = Path(root).resolve()
    vulnerabilities = []
    skipped_files = []
    
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
    
    report = generate_markdown_report(vulnerabilities, skipped_files)
    with open(output, "w") as f:
        f.write(report)
    
    click.echo(f"✅ Report saved to {output}")
    return 0

if __name__ == "__main__":
    analyze()