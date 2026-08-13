import agentwall


def test_package_has_version():
    assert isinstance(agentwall.__version__, str)
    assert agentwall.__version__
