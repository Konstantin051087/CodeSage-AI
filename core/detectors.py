import libcst as cst
from libcst.metadata import PositionProvider

class SQLInjectionDetector(cst.CSTVisitor):
    METADATA_DEPENDENCIES = (PositionProvider,)
    
    def __init__(self):
        self.vulnerabilities = []
    
    def visit_Call(self, node: cst.Call):
        # Проверяем вызовы cursor.execute()
        if (
            isinstance(node.func, cst.Attribute) and
            node.func.attr.value == "execute" and
            self._is_sql_query(node.args[0].value)
        ):
            pos = self.get_metadata(PositionProvider, node).start
            self.vulnerabilities.append({
                "type": "sql_injection",
                "file": "current_file",  # Будет заменено в cli.py
                "line": pos.line,
                "code": self._get_code_snippet(node),
                "fix": self._generate_fix(node)
            })
    
    def _is_sql_query(self, node: cst.BaseExpression) -> bool:
        """Проверяет, что аргумент — строка с SQL-запросом без параметризации"""
        if isinstance(node, cst.FormattedString):
            return True  # f-строки всегда опасны
        if isinstance(node, cst.BinaryOperation):
            return True  # Конкатенация строк
        if isinstance(node, cst.SimpleString):
            return "%" in node.value or "+" in node.value  # Старый стиль форматирования
        return False
    
    def _get_code_snippet(self, node: cst.Call) -> str:
        return cst.Module([]).code_for_node(node)
    
    def _generate_fix(self, node: cst.Call) -> str:
        # Пример исправления для f-строки
        return (
            "# Вместо:\n"
            "cursor.execute(f\"SELECT * FROM users WHERE name = {name}\")\n"
            "# Используйте:\n"
            "cursor.execute(\"SELECT * FROM users WHERE name = %s\", (name,))"
        )