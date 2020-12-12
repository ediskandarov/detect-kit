from datetime import datetime

import pytest

from detect_kit.config import DomainCheck
from tests.types import WhoisFactory

pytestmark = pytest.mark.detection


def test_domain_expiration(domain: DomainCheck, get_whois: WhoisFactory) -> None:
    whois = get_whois(domain)
    now = datetime.now()
    assert whois.expiration_date > now


def test_domain_registrar(domain: DomainCheck, get_whois: WhoisFactory) -> None:
    domain_whois = get_whois(domain)
    if domain.expected_registrar_name is not None:
        assert domain.expected_registrar_name.lower() == domain_whois.registrar.lower()
