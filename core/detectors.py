import libcst as cst
from libcst import CSTVisitor, Name, Attribute, Call
from libcst.metadata import PositionProvider

class SQLInjectionDetector(CSTVisitor):
    METADATA_DEPENDENCIES = (PositionProvider,)

    def __init__(self):
        self.vulnerabilities = []

    def visit_Call(self, node: cst.Call):
        if (
            isinstance(node.func, cst.Attribute) and
            node.func.attr.value == "execute"
        ):
            # 2+ аргументов — скорее всего параметризованный запрос (безопасно)
            if len(node.args) >= 2:
                return

            # 0 аргументов — нечего анализировать
            if len(node.args) == 0:
                return

            query_arg = node.args[0].value
            if self._is_dangerous_sql_expression(query_arg):
                pos = self.get_metadata(PositionProvider, node).start
                self.vulnerabilities.append({
                    "type": "sql_injection",
                    "file": "current_file",
                    "line": pos.line,
                    "code": self._get_code_snippet(node),
                    "fix": self._generate_fix(node)
                })

    def _is_dangerous_sql_expression(self, node: cst.BaseExpression) -> bool:
        if isinstance(node, cst.FormattedString):
            return True
        if isinstance(node, cst.BinaryOperation):
            return isinstance(node.operator, (cst.Add, cst.Modulo))
        if isinstance(node, cst.SimpleString):
            return False
        return False

    def _get_code_snippet(self, node: cst.Call) -> str:
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

    DANGEROUS_FUNCTIONS = {
        "eval": "Avoid eval() — use ast.literal_eval for safe evaluation.",
        "exec": "Avoid exec() — refactor to avoid dynamic code execution.",
        "pickle.loads": "Avoid pickle.loads() — use json.loads for safe deserialization.",
        "pickle.load": "Avoid pickle.load() — use json.load for safe deserialization.",
        "jsonpickle.decode": "Avoid jsonpickle.decode() — use standard json module.",
    }

    def __init__(self):
        self.vulnerabilities = []

    def visit_Call(self, node: Call) -> None:
        func = node.func
        full_name = None

        if isinstance(func, Name):
            full_name = func.value
        elif isinstance(func, Attribute):
            value = func.value
            attr = func.attr
            if isinstance(value, Name) and isinstance(attr, Name):
                full_name = f"{value.value}.{attr.value}"

        if full_name and full_name in self.DANGEROUS_FUNCTIONS:
            pos = self.get_metadata(PositionProvider, node).start
            self.vulnerabilities.append({
                "type": "dangerous_function",
                "function": full_name,
                "file": "current_file",
                "line": pos.line,
                # 🔴 Критическое исправление: добавлено поле fix
                "fix": self.DANGEROUS_FUNCTIONS[full_name]
            })