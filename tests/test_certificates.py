from datetime import datetime

import pytest

from detect_kit.config import CertificateCheck
from tests.types import CertificateFactory

pytestmark = pytest.mark.detection


def test_certificate_is_not_expired(
    cert_cfg: CertificateCheck, get_certificate: CertificateFactory
):
    cert = get_certificate(cert_cfg)

    now = datetime.utcnow()
    if cert_cfg.expiration_threshold_days is not None:
        if cert.not_before is not None:
            assert (
                now > cert.not_before
            ), f"Certificate not valid before {cert.not_before}"
        if cert.not_after is not None:
            assert (
                now < cert.not_after
            ), f"Certificate is not valid after {cert.not_after}"


def test_certificate_issuer(
    cert_cfg: CertificateCheck, get_certificate: CertificateFactory
):
    cert = get_certificate(cert_cfg)

    if cert_cfg.expected_issuer_organisation_name is not None:
        if cert.issuer.organization_name is not None:
            assert (
                cert_cfg.expected_issuer_organisation_name.lower()
                == cert.issuer.organization_name.lower()
            )


def test_certificate_match_sites(
    cert_cfg: CertificateCheck, get_certificate: CertificateFactory
):
    cert = get_certificate(cert_cfg)

    assert cert.match_site(
        cert_cfg.site
    ), f"Certificate does not match for site {cert_cfg.site}"

    if cert_cfg.should_match_sites is not None:
        for site in cert_cfg.should_match_sites:
            assert cert.match_site(site), f"Certificate does not match for site {site}"
