import libcst as cst
from core.detectors import SQLInjectionDetector

def test_fstring_vulnerability():
    code = """
    def get_user(name):
        cursor.execute(f"SELECT * FROM users WHERE name = {name}")
    """
    module = cst.parse_module(code)
    detector = SQLInjectionDetector()
    wrapper = cst.MetadataWrapper(module)
    wrapper.visit(detector)
    assert len(detector.vulnerabilities) == 1
    assert detector.vulnerabilities[0]["line"] == 3