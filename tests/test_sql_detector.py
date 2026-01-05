import libcst as cst
import textwrap
from core.detectors import SQLInjectionDetector, DangerousFunctionDetector


def test_fstring_vulnerability():
    code = textwrap.dedent("""
    def get_user(name):
        cursor.execute(f"SELECT * FROM users WHERE name = {name}")
    """)
    module = cst.parse_module(code)
    detector = SQLInjectionDetector()
    wrapper = cst.MetadataWrapper(module)
    wrapper.visit(detector)
    assert len(detector.vulnerabilities) == 1
    assert detector.vulnerabilities[0]["line"] == 3


def test_sql_injection_with_plus():
    code = '''cursor.execute("SELECT * FROM users WHERE id = '" + user_id + "'")'''
    detector = SQLInjectionDetector()
    module = cst.parse_module(code)
    wrapper = cst.MetadataWrapper(module)
    wrapper.visit(detector)
    assert len(detector.vulnerabilities) == 1


def test_sql_injection_with_percent():
    code = '''cursor.execute("SELECT * FROM users WHERE id = '%s'" % user_id)'''
    detector = SQLInjectionDetector()
    module = cst.parse_module(code)
    wrapper = cst.MetadataWrapper(module)
    wrapper.visit(detector)
    assert len(detector.vulnerabilities) == 1


def test_safe_query():
    code = '''cursor.execute("SELECT * FROM users WHERE name = %s", (name,))'''
    detector = SQLInjectionDetector()
    module = cst.parse_module(code)
    wrapper = cst.MetadataWrapper(module)
    wrapper.visit(detector)
    assert len(detector.vulnerabilities) == 0


def test_pickle_loads():
    code = '''
import pickle
data = b"..."
result = pickle.loads(data)
'''
    detector = DangerousFunctionDetector()
    module = cst.parse_module(code)
    wrapper = cst.MetadataWrapper(module)
    wrapper.visit(detector)
    assert len(detector.vulnerabilities) == 1


# === Дополнительные тесты для 95%+ покрытия ===

def test_execute_no_args():
    """cursor.execute() без аргументов — не уязвимость"""
    code = 'cursor.execute()'
    detector = SQLInjectionDetector()
    module = cst.parse_module(code)
    wrapper = cst.MetadataWrapper(module)
    wrapper.visit(detector)
    assert len(detector.vulnerabilities) == 0


def test_safe_simple_string():
    """Простая строка без форматирования — не уязвимость"""
    code = 'cursor.execute("SELECT * FROM users")'
    detector = SQLInjectionDetector()
    module = cst.parse_module(code)
    wrapper = cst.MetadataWrapper(module)
    wrapper.visit(detector)
    assert len(detector.vulnerabilities) == 0


def test_eval_and_exec():
    """Проверка опасных функций: eval, exec"""
    code = '''
eval("__import__('os').system('rm -rf /')")
exec("print('hello')")
'''
    detector = DangerousFunctionDetector()
    module = cst.parse_module(code)
    wrapper = cst.MetadataWrapper(module)
    wrapper.visit(detector)
    assert len(detector.vulnerabilities) == 2
    functions = {v["function"] for v in detector.vulnerabilities}
    assert functions == {"eval", "exec"}


def test_pickle_load():
    """Также ловим pickle.load (без 's')"""
    code = '''
import pickle
with open("data.pkl", "rb") as f:
    obj = pickle.load(f)
'''
    detector = DangerousFunctionDetector()
    module = cst.parse_module(code)
    wrapper = cst.MetadataWrapper(module)
    wrapper.visit(detector)
    assert len(detector.vulnerabilities) == 1
    assert detector.vulnerabilities[0]["function"] == "pickle.load"


def test_complex_attribute_not_dangerous():
    """Вызов неопасной функции через атрибут — не должно сработать"""
    code = '''
import json
json.dumps(data)
'''
    detector = DangerousFunctionDetector()
    module = cst.parse_module(code)
    wrapper = cst.MetadataWrapper(module)
    wrapper.visit(detector)
    assert len(detector.vulnerabilities) == 0


def test_non_string_argument():
    """Проверка, что если аргумент — не строка и не выражение — то это не уязвимость"""
    code = '''
x = 42
cursor.execute(x)
'''
    detector = SQLInjectionDetector()
    module = cst.parse_module(code)
    wrapper = cst.MetadataWrapper(module)
    wrapper.visit(detector)
    assert len(detector.vulnerabilities) == 0