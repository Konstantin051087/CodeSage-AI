# Файл: core/reporter.py (обновленная версия)
import os
from .ai.ai_explainer import AIExplainer

def generate_markdown_report(vulnerabilities: list, skipped_files: list = None, use_ai=True) -> str:
    """
    Генерирует Markdown-отчет с результатами анализа
    
    Args:
        vulnerabilities: Список найденных уязвимостей
        skipped_files: Список файлов с ошибками синтаксиса
        use_ai: Использовать ИИ для генерации объяснений
    
    Returns:
        str: Сгенерированный отчет в формате Markdown
    """
    if skipped_files is None:
        skipped_files = []
    
    report_lines = []
    
    # Добавлен блок для пропущенных файлов
    if skipped_files:
        report_lines.append("⚠️ **Skipped files due to syntax errors**:\n")
        for file in skipped_files:
            report_lines.append(f"- `{file}`")
        report_lines.append("\n")
    
    # Основной отчет по уязвимостям
    if not vulnerabilities:
        if not skipped_files:  # Только если нет пропущенных файлов
            report_lines.append("✅ **CodeSage Report**: No vulnerabilities found.")
        return "\n".join(report_lines)
    
    # Инициализация AIExplainer
    ai_explainer = AIExplainer(use_ai=use_ai)
    
    report_lines.append("⚠️ **CodeSage Security Report**\n")
    
    for idx, vuln in enumerate(vulnerabilities, 1):
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
            )
            
            # Добавляем AI-объяснение если включено
            if use_ai:
                ai_result = ai_explainer.explain_vulnerability("sql_injection", code)
                report_lines.append(f"**AI Explanation**:\n{ai_result['explanation']}\n")
                
                if ai_result["keywords"]:
                    report_lines.append(f"**Keywords**: {', '.join(ai_result['keywords'])}\n")
            else:
                report_lines.append("**Business Impact**: Risk of full database leak → GDPR fines up to €20M.\n")
                
        elif vuln_type == "dangerous_function":
            function = vuln.get("function", "unknown")
            # Используем fix из уязвимости
            fix = vuln.get("fix", "Avoid using this dangerous function. Prefer safer alternatives.")
            
            report_lines.append(
                f"### ⚡ Dangerous Function `{function}` (Line {line})\n"
                f"**Fix**: {fix}\n"
            )
            
            # Добавляем AI-объяснение если включено
            if use_ai:
                ai_result = ai_explainer.explain_vulnerability("dangerous_function", function)
                report_lines.append(f"**AI Explanation**:\n{ai_result['explanation']}\n")
                
                if ai_result["keywords"]:
                    report_lines.append(f"**Keywords**: {', '.join(ai_result['keywords'])}\n")
            else:
                report_lines.append("**Business Impact**: Remote code execution → server takeover.\n")
        
        # Добавляем разделитель между уязвимостями
        if idx < len(vulnerabilities):
            report_lines.append("---\n")
    
    return "\n".join(report_lines)