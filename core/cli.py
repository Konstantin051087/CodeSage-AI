import click
import libcst as cst
from .detectors import SQLInjectionDetector, DangerousFunctionDetector
from .reporter import generate_markdown_report
import os

@click.command()
@click.option("--path", required=True, help="Path to Python file or directory")
@click.option("--output", default="report.md", help="Output report file")
def analyze(path, output):
    vulnerabilities = []
    
    if os.path.isfile(path):
        files = [path]
    else:
        files = [os.path.join(root, f) for root, _, files in os.walk(path) for f in files if f.endswith(".py")]
    
    for file_path in files:
        with open(file_path, "r") as f:
            code = f.read()
        
        module = cst.parse_module(code)
        wrapper = cst.MetadataWrapper(module)
        
        # Запуск детекторов
        sql_detector = SQLInjectionDetector()
        dangerous_detector = DangerousFunctionDetector()
        
        wrapper.visit(sql_detector)
        wrapper.visit(dangerous_detector)
        
        # Добавление пути к уязвимостям
        for vuln in sql_detector.vulnerabilities + dangerous_detector.vulnerabilities:
            vuln["file"] = os.path.relpath(file_path)
        
        vulnerabilities.extend(sql_detector.vulnerabilities)
        vulnerabilities.extend(dangerous_detector.vulnerabilities)
    
    report = generate_markdown_report(vulnerabilities)
    with open(output, "w") as f:
        f.write(report)
    
    click.echo(f"✅ Report saved to {output}")

if __name__ == "__main__":
    analyze()
