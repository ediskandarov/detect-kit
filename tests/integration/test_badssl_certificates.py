import pytest

from detect_kit.config import CertificateCheck
from tests.types import CertificateFactory

pytestmark = pytest.mark.lib

@pytest.mark.parametrize(
    "badssl_site, expected",
    [
        ("https://expired.badssl.com/", True),
        ("https://wrong.host.badssl.com/", False),
        ("https://self-signed.badssl.com/", False),
        ("https://untrusted-root.badssl.com/", False),
        ("https://revoked.badssl.com/", False),
        ("https://pinning-test.badssl.com/", False),
    ],
)
def test_badssl_expired(get_certificate: CertificateFactory, badssl_site, expected):
    cert_cfg = CertificateCheck(
        site=badssl_site,
    )
    cert = get_certificate(cert_cfg)

    assert cert.ssl_info.certificate.has_expired() == expected


@pytest.mark.parametrize(
    "badssl_site, expected",
    [
        ("https://expired.badssl.com/", True),
        ("https://wrong.host.badssl.com/", True),
        ("https://self-signed.badssl.com/", False),
        ("https://untrusted-root.badssl.com/", False),
        pytest.param("https://revoked.badssl.com/", False, marks=pytest.mark.xfail),
        pytest.param("https://pinning-test.badssl.com/", False, marks=pytest.mark.xfail),
    ],
)
def test_badssl_untrusted(get_certificate: CertificateFactory, badssl_site, expected):
    cert_cfg = CertificateCheck(
        site=badssl_site,
    )
    cert = get_certificate(cert_cfg)

    assert cert.verify() == expected


@pytest.mark.parametrize(
    "badssl_site, expected",
    [
        ("https://expired.badssl.com/", True),
        ("https://wrong.host.badssl.com/", False),
        ("https://self-signed.badssl.com/", True),
        ("https://untrusted-root.badssl.com/", True),
        ("https://revoked.badssl.com/", True),
        ("https://pinning-test.badssl.com/", True),
    ],
)
def test_badssl_hostname_matches(get_certificate: CertificateFactory, badssl_site, expected):
    cert_cfg = CertificateCheck(
        site=badssl_site,
    )
    cert = get_certificate(cert_cfg)

    assert cert.match_site(badssl_site) == expected
