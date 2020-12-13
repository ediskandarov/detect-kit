from datetime import datetime, timedelta

import pytest

from detect_kit.config import CertificateCheck
from tests.types import CertificateFactory

pytestmark = pytest.mark.detection


def test_certificate_is_active(
    cert_cfg: CertificateCheck, get_certificate: CertificateFactory
) -> None:
    cert = get_certificate(cert_cfg)

    assert not cert.ssl_info.certificate.has_expired()


def test_certificate_expiration_check(
    cert_cfg: CertificateCheck, get_certificate: CertificateFactory
) -> None:
    cert = get_certificate(cert_cfg)

    if cert_cfg.expiration_threshold_days is None or cert.not_after is None:
        return

    now = datetime.utcnow()
    threshold = timedelta(days=cert_cfg.expiration_threshold_days)
    notify_on = cert.not_after - threshold
    assert now < notify_on, f"Warning! Certificate will expire in less than {threshold}"


def test_certificate_expiration_check_relative(
    cert_cfg: CertificateCheck, get_certificate: CertificateFactory
) -> None:
    cert = get_certificate(cert_cfg)

    if (
        cert_cfg.expiration_threshold_relative is None
        or cert.not_after is None
        or cert.not_before is None
    ):
        return

    now = datetime.utcnow()
    certificate_valid_perior = cert.not_after - cert.not_before
    threshold = certificate_valid_perior * cert_cfg.expiration_threshold_relative / 100
    notify_on = cert.not_after - threshold
    assert now < notify_on, f"Warning! Certificate will expire in less than {threshold}"


def test_certificate_issuer(
    cert_cfg: CertificateCheck, get_certificate: CertificateFactory
) -> None:
    cert = get_certificate(cert_cfg)

    if (
        cert_cfg.expected_issuer_organisation_name is None
        or cert.issuer_common_name is None
    ):
        return

    assert (
        cert_cfg.expected_issuer_organisation_name.lower()
        == cert.issuer_common_name.lower()
    )


def test_certificate_match_sites(
    cert_cfg: CertificateCheck, get_certificate: CertificateFactory
) -> None:
    cert = get_certificate(cert_cfg)

    assert cert.match_site(
        cert_cfg.site
    ), f"Certificate does not match for site {cert_cfg.site}"

    if cert_cfg.should_match_sites is None:
        return

    for site in cert_cfg.should_match_sites:
        assert cert.match_site(site), f"Certificate does not match for site {site}"


def test_certificate_is_trusted(
    cert_cfg: CertificateCheck, get_certificate: CertificateFactory
) -> None:
    cert = get_certificate(cert_cfg)

    assert cert.verify()
