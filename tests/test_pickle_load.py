def test_pickle_loads():
    code = "import pickle\npickle.loads(user_input)"
    module = cst.parse_module(code)
    detector = DangerousFunctionDetector()
    wrapper = cst.MetadataWrapper(module)
    wrapper.visit(detector)
    assert len(detector.vulnerabilities) == 1