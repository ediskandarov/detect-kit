from pathlib import Path
from typing import Any, Dict

import pytest
from whois import WhoisEntry, whois

from detect_kit.config import CertificateCheck, DomainCheck, Settings
from detect_kit.models import CertificateModel

from .types import CertificateFactory, WhoisFactory


def certificate_ids(certificate: CertificateCheck) -> str:
    return certificate.site


def domain_ids(domain: DomainCheck) -> str:
    return domain.domain


def pytest_generate_tests(metafunc: Any) -> None:
    config_file = Path(__file__).parent / "tests.config.yaml"
    settings = Settings.from_config_file(config_file)

    if "cert_cfg" in metafunc.fixturenames:
        metafunc.parametrize(
            "cert_cfg", settings.detect_kit.certificates, ids=certificate_ids
        )

    if "domain" in metafunc.fixturenames:
        metafunc.parametrize("domain", settings.detect_kit.domains, ids=domain_ids)


@pytest.fixture(scope="session")
def get_certificate() -> CertificateFactory:
    cache: Dict[str, CertificateModel] = {}

    def _get_certificate(cert_check: CertificateCheck) -> CertificateModel:
        site = cert_check.site
        if site not in cache:
            cache[site] = CertificateModel.from_url(site)
        return cache[site]

    return _get_certificate


@pytest.fixture(scope="session")
def get_whois() -> WhoisFactory:
    cache: Dict[str, WhoisEntry] = {}

    def _get_whois(domain_check: DomainCheck) -> WhoisEntry:
        domain = domain_check.domain
        if domain not in cache:
            cache[domain] = whois(domain)
        return cache[domain]

    return _get_whois
