from datetime import datetime

import whois


def test_python_org_domain():
    domain = whois.whois("python.org")

    now = datetime.now()
    assert domain.expiration_date > now
    assert domain.registrar == "GANDI SAS"
    expected_domains = {
        "ns-2046.awsdns-63.co.uk",
        "ns-484.awsdns-60.com",
        "ns-981.awsdns-58.net",
        "ns-1134.awsdns-13.org",
    }
    assert expected_domains == {d.lower() for d in domain.name_servers}
