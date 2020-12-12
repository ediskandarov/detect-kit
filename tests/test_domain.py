from datetime import datetime
from typing import Callable, TypeVar

import whois
from whois import WhoisEntry

from detect_kit.config import DomainCheck

get_whois_T = TypeVar("get_whois_T", bound=Callable[[DomainCheck], WhoisEntry])

# pytestmark = pytest.mark.skip


def test_python_org_domain() -> None:
    domain = whois.whois("python.org")

    now = datetime.now()
    assert domain.expiration_date > now
    assert domain.registrar.lower() == "GANDI SAS".lower()
    expected_domains = {
        "ns-2046.awsdns-63.co.uk",
        "ns-484.awsdns-60.com",
        "ns-981.awsdns-58.net",
        "ns-1134.awsdns-13.org",
    }
    assert expected_domains == {d.lower() for d in domain.name_servers}


def test_domain_expiration(domain: DomainCheck, get_whois: get_whois_T) -> None:
    whois = get_whois(domain)

    now = datetime.now()
    assert whois.expiration_date > now


def test_domain_registrar(domain: DomainCheck, get_whois: get_whois_T) -> None:
    domain_whois = get_whois(domain)
    if domain.expected_registrar_name is not None:
        assert domain.expected_registrar_name.lower() == domain_whois.registrar.lower()
