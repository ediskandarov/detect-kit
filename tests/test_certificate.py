from datetime import datetime

from detect_kit.models import CertificateModel


def test_fetch_python_org_domain_certificate():
    site = "https://python.org/"
    cert = CertificateModel.from_url(site)

    assert cert.subject.common_name == "www.python.org"
    assert cert.issuer.common_name == "DigiCert SHA2 Extended Validation Server CA"
    cert.match_hostname("python.org")


def test_model_parses_python_org_cert():
    python_org_cert = {
        "OCSP": ("http://ocsp.digicert.com",),
        "caIssuers": (
            "http://cacerts.digicert.com/DigiCertSHA2ExtendedValidationServerCA.crt",
        ),
        "crlDistributionPoints": (
            "http://crl3.digicert.com/sha2-ev-server-g3.crl",
            "http://crl4.digicert.com/sha2-ev-server-g3.crl",
        ),
        "issuer": (
            (("countryName", "US"),),
            (("organizationName", "DigiCert Inc"),),
            (("organizationalUnitName", "www.digicert.com"),),
            (("commonName", "DigiCert SHA2 Extended Validation Server CA"),),
        ),
        "notAfter": "Oct 31 00:00:00 2021 GMT",
        "notBefore": "Sep 29 00:00:00 2020 GMT",
        "serialNumber": "0A0BEEEAB294FC6DFA6E556CBB94BA07",
        "subject": (
            (("businessCategory", "Private Organization"),),
            (("jurisdictionCountryName", "US"),),
            (("jurisdictionStateOrProvinceName", "Delaware"),),
            (("serialNumber", "3359300"),),
            (("countryName", "US"),),
            (("stateOrProvinceName", "Oregon"),),
            (("localityName", "Beaverton"),),
            (("organizationName", "Python Software Foundation"),),
            (("commonName", "www.python.org"),),
        ),
        "subjectAltName": (
            ("DNS", "www.python.org"),
            ("DNS", "docs.python.org"),
            ("DNS", "bugs.python.org"),
            ("DNS", "wiki.python.org"),
            ("DNS", "hg.python.org"),
            ("DNS", "mail.python.org"),
            ("DNS", "pypi.python.org"),
            ("DNS", "packaging.python.org"),
            ("DNS", "login.python.org"),
            ("DNS", "us.pycon.org"),
            ("DNS", "pypi.org"),
            ("DNS", "pypi.io"),
            ("DNS", "docs.pypi.io"),
            ("DNS", "docs.pypi.org"),
            ("DNS", "donate.pypi.io"),
            ("DNS", "donate.pypi.org"),
            ("DNS", "devguide.python.org"),
            ("DNS", "www.bugs.python.org"),
            ("DNS", "python.org"),
            ("DNS", "downloads.python.org"),
        ),
        "version": 3,
    }

    crt: CertificateModel = CertificateModel.parse_obj(python_org_cert)

    assert crt.not_before == datetime(2020, 9, 29)
    assert crt.not_after == datetime(2021, 10, 31)
    assert crt.issuer.organization_name == "DigiCert Inc"
    assert crt.subject.common_name == "www.python.org"
    assert crt.match_hostname("www.python.org")
    assert crt.match_hostname("pypi.io")
    assert not crt.match_hostname("example.com")


def test_model_parses_invalid_cert():
    python_org_cert = {
        "issuer": tuple(),
        "subject": tuple(),
    }

    crt: CertificateModel = CertificateModel.parse_obj(python_org_cert)

    assert crt.not_before is None
    assert crt.not_after is None
    assert crt.issuer.organization_name is None
    assert crt.subject.common_name is None
    assert not crt.match_hostname("www.python.org")
