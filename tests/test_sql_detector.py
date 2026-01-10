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
    code = 'cursor.execute("SELECT * FROM users WHERE id = \'" + user_id + "\'")'
    detector = SQLInjectionDetector()
    module = cst.parse_module(code)
    wrapper = cst.MetadataWrapper(module)
    wrapper.visit(detector)
    
    assert len(detector.vulnerabilities) == 1

def test_sql_injection_with_percent():
    code = 'cursor.execute("SELECT * FROM users WHERE id = \'%s\'" % user_id)'
    detector = SQLInjectionDetector()
    module = cst.parse_module(code)
    wrapper = cst.MetadataWrapper(module)
    wrapper.visit(detector)
    
    assert len(detector.vulnerabilities) == 1

def test_safe_query():
    code = 'cursor.execute("SELECT * FROM users WHERE name = %s", (name,))'
    detector = SQLInjectionDetector()
    module = cst.parse_module(code)
    wrapper = cst.MetadataWrapper(module)
    wrapper.visit(detector)
    
    assert len(detector.vulnerabilities) == 0

# Исправленные тесты с правильным форматированием
def test_pickle_loads():
    code = textwrap.dedent('''
    import pickle
    data = b"..."
    result = pickle.loads(data)
    ''')
    module = cst.parse_module(code)
    detector = DangerousFunctionDetector()
    wrapper = cst.MetadataWrapper(module)
    wrapper.visit(detector)
    
    assert len(detector.vulnerabilities) == 1

def test_exec():
    code = textwrap.dedent('''
    # Демонстрация опасного использования exec()
    user_input = "print('Hello')"
    exec(user_input)
    ''')
    detector = DangerousFunctionDetector()
    module = cst.parse_module(code)
    wrapper = cst.MetadataWrapper(module)
    wrapper.visit(detector)
    
    assert len(detector.vulnerabilities) == 1
    assert detector.vulnerabilities[0]["function"] == "exec"

def test_eval():
    code = textwrap.dedent('''
    # Демонстрация опасного использования eval()
    user_input = "__import__('os').system('echo hello')"
    eval(user_input)
    ''')
    detector = DangerousFunctionDetector()
    module = cst.parse_module(code)
    wrapper = cst.MetadataWrapper(module)
    wrapper.visit(detector)
    
    assert len(detector.vulnerabilities) == 1
    assert detector.vulnerabilities[0]["function"] == "eval"

def test_pickle_load():
    code = textwrap.dedent('''
    import pickle
    with open("data.pkl", "rb") as f:
        obj = pickle.load(f)
    ''')
    detector = DangerousFunctionDetector()
    module = cst.parse_module(code)
    wrapper = cst.MetadataWrapper(module)
    wrapper.visit(detector)
    
    assert len(detector.vulnerabilities) == 1
    assert detector.vulnerabilities[0]["function"] == "pickle.load"

def test_jsonpickle_decode():
    code = textwrap.dedent('''
    import jsonpickle
    result = jsonpickle.decode(user_input)
    ''')
    detector = DangerousFunctionDetector()
    module = cst.parse_module(code)
    wrapper = cst.MetadataWrapper(module)
    wrapper.visit(detector)
    
    assert len(detector.vulnerabilities) == 1
    assert detector.vulnerabilities[0]["function"] == "jsonpickle.decode"

def test_safe_function():
    code = textwrap.dedent('''
    import json
    result = json.dumps(data)
    ''')
    detector = DangerousFunctionDetector()
    module = cst.parse_module(code)
    wrapper = cst.MetadataWrapper(module)
    wrapper.visit(detector)
    
    assert len(detector.vulnerabilities) == 0

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