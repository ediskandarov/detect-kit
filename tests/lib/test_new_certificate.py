from detect_kit.certificate import CertificateWrapper


def test_certificate_wrapper() -> None:
    cw = CertificateWrapper.from_url("https://yandex.ru")
    assert cw.not_after > cw.not_before
    assert cw.issuer_common_name == "Yandex CA"
    assert len(cw.subject_alt_name) > 1
    assert cw.match_hostname("yandex.net")
    assert not cw.match_hostname("example.com")
    assert cw.match_site("https://yandex.net")
    assert not cw.match_site("https://example.com")
    assert cw.verify()
