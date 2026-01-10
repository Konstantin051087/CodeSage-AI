import libcst as cst
import textwrap
from core.detectors import DangerousFunctionDetector

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
    assert detector.vulnerabilities[0]["function"] == "pickle.loads"
    assert "json.loads" in detector.vulnerabilities[0]["fix"]

def test_eval_and_exec():
    code = textwrap.dedent('''
    eval("__import__('os').system('rm -rf /')")
    exec("print('hello')")
    ''')
    detector = DangerousFunctionDetector()
    module = cst.parse_module(code)
    wrapper = cst.MetadataWrapper(module)
    wrapper.visit(detector)
    
    assert len(detector.vulnerabilities) == 2
    functions = {v["function"] for v in detector.vulnerabilities}
    assert functions == {"eval", "exec"}

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