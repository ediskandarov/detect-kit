from datetime import datetime

import pytest
import whois

pytestmark = pytest.mark.lib


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
