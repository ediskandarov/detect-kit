from pathlib import Path

from detect_kit.config import Settings


def pytest_generate_tests(metafunc):
    config_file = Path(__file__).parent / "tests.config.yaml"
    settings = Settings.from_config_file(config_file)

    certificates = [check.site for check in settings.detect_kit.certificates]
    domains = [check.domain for check in settings.detect_kit.domains]

    if "site" in metafunc.fixturenames:
        metafunc.parametrize("site", certificates)

    if "domain" in metafunc.fixturenames:
        metafunc.parametrize("domain", certificates)
