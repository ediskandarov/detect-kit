from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional
from urllib.parse import urlparse

import service_identity
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from service_identity.cryptography import verify_certificate_hostname


@dataclass
class CertificateWrapper:
    certificate: x509.Certificate

    @classmethod
    def from_url(cls, url: str, timeout: float = 5) -> CertificateWrapper:
        bits = urlparse(url)
        hostname, _, port = bits.netloc.partition(":")
        port = port or "443"

        context = ssl.create_default_context()
        with socket.create_connection((hostname, int(port)), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_data = ssock.getpeercert(binary_form=True)

        if der_data:
            cert = x509.load_der_x509_certificate(der_data, default_backend())
        else:
            raise ValueError(
                (
                    "There is no certificate for the peer "
                    "on the other end of the connection"
                )
            )

        return cls(certificate=cert)

    @property
    def not_before(self) -> datetime:
        return self.certificate.not_valid_before

    @property
    def not_after(self) -> datetime:
        return self.certificate.not_valid_after

    @property
    def issuer_common_name(self) -> Optional[str]:
        try:
            names = self.certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            return names[0].value
        except x509.ExtensionNotFound:
            return None

    @property
    def subject_common_name(self) -> Optional[str]:
        try:
            names = self.certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            return names[0].value
        except x509.ExtensionNotFound:
            return None

    @property
    def subject_alt_name(self) -> List[str]:
        try:
            ext = self.certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            return ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            return []

    def match_hostname(self, hostname: str) -> bool:
        try:
            verify_certificate_hostname(self.certificate, hostname)
        except service_identity.VerificationError:
            return False
        else:
            return True

    def match_site(self, site: str) -> bool:
        bits = urlparse(site)
        hostname, _, _ = bits.netloc.partition(":")
        return self.match_hostname(hostname)

    # def verify(self) -> bool:
    #     # https://yothenberg.com/validate-x509-certificate-in-python.html
    #     # https://github.com/pyca/pyopenssl/pull/948/files
    #     store = crypto.X509Store()

    #     root_cert = None
    #     verified_cert = None
    #     store.add_cert(root_cert)
    #     store_ctx = X509StoreContext(store, verified_cert, chain=chain)
    #     return store_ctx.verify_certificate() is None
