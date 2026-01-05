import libcst as cst
from libcst import CSTVisitor, Name, Attribute, Call
from libcst.metadata import PositionProvider


class SQLInjectionDetector(CSTVisitor):
    METADATA_DEPENDENCIES = (PositionProvider,)

    def __init__(self):
        self.vulnerabilities = []

    def visit_Call(self, node: cst.Call):
        # Проверяем вызовы вида cursor.execute(...)
        if (
            isinstance(node.func, cst.Attribute) and
            node.func.attr.value == "execute"
        ):
            # 🔒 Безопасный запрос: если передано 2+ аргумента → параметризованный вызов
            if len(node.args) >= 2:
                return  # НЕ уязвимость

            # Опасен только вызов с одним аргументом (строкой)
            if len(node.args) == 0:
                return

            query_arg = node.args[0].value
            if self._is_dangerous_sql_expression(query_arg):
                pos = self.get_metadata(PositionProvider, node).start
                self.vulnerabilities.append({
                    "type": "sql_injection",
                    "file": "current_file",  # будет заменено в cli.py
                    "line": pos.line,
                    "code": self._get_code_snippet(node),
                    "fix": self._generate_fix(node)
                })

    def _is_dangerous_sql_expression(self, node: cst.BaseExpression) -> bool:
        """Определяет, является ли выражение потенциально опасным для SQL-инъекции."""
        # f-строки — всегда опасны
        if isinstance(node, cst.FormattedString):
            return True

        # Бинарные операции: конкатенация (+) или форматирование (%)
        if isinstance(node, cst.BinaryOperation):
            return isinstance(node.operator, (cst.Add, cst.Modulo))

        # Простая строка сама по себе НЕ опасна (даже если содержит %s)
        # Пример: "SELECT * FROM t WHERE id = %s" — безопасна
        if isinstance(node, cst.SimpleString):
            return False

        return False

    def _get_code_snippet(self, node: cst.Call) -> str:
        # Используем пустой модуль для генерации сниппета
        return cst.Module([]).code_for_node(node)

    def _generate_fix(self, node: cst.Call) -> str:
        return (
            "# Вместо:\n"
            "# cursor.execute(f\"SELECT * FROM users WHERE name = {name}\")\n"
            "# или\n"
            "# cursor.execute(\"SELECT * FROM users WHERE id = \" + user_id)\n"
            "# Используйте параметризованный запрос:\n"
            "cursor.execute(\"SELECT * FROM users WHERE name = %s\", (name,))"
        )


class DangerousFunctionDetector(CSTVisitor):
    METADATA_DEPENDENCIES = (PositionProvider,)

    def __init__(self):
        self.vulnerabilities = []

    def visit_Call(self, node: Call) -> None:
        func = node.func
        full_name = None

        # Прямой вызов: eval(), exec()
        if isinstance(func, Name):
            full_name = func.value

        # Атрибутный вызов: pickle.loads(), yaml.load()
        elif isinstance(func, Attribute):
            value = func.value
            attr = func.attr
            # Обрабатываем только простые случаи: модуль.функция
            if isinstance(value, Name) and isinstance(attr, Name):
                full_name = f"{value.value}.{attr.value}"

        dangerous = {
            "eval",
            "exec",
            "pickle.loads",
            "pickle.load",
            # Можно расширить: "yaml.load", "subprocess.Popen" и т.д.
        }

        if full_name and full_name in dangerous:
            pos = self.get_metadata(PositionProvider, node).start
            self.vulnerabilities.append({
                "type": "dangerous_function",
                "function": full_name,
                "file": "current_file",
                "line": pos.line
            })
