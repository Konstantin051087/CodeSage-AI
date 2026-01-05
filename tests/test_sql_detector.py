import libcst as cst
import textwrap
from core.detectors import SQLInjectionDetector
from core.detectors import DangerousFunctionDetector

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

def test_pickle_loads():
    code = "import pickle\npickle.loads(user_input)"
    module = cst.parse_module(code)
    detector = DangerousFunctionDetector()
    wrapper = cst.MetadataWrapper(module)
    wrapper.visit(detector)
    assert len(detector.vulnerabilities) == 1

def test_safe_query():
    code = 'cursor.execute("SELECT * FROM users WHERE name = %s", (name,))'
    # Должен вернуть 0 уязвимостей
    assert len(analyze_code(code)) == 0