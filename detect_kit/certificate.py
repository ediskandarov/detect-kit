from __future__ import annotations

import socket
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional
from urllib.parse import urlparse

import idna
import service_identity
from cryptography import x509
from cryptography.x509.oid import NameOID
from OpenSSL import SSL, crypto
from service_identity.cryptography import verify_certificate_hostname


@dataclass
class SSLInfo:
    certificate: crypto.X509
    chain: List[crypto.x509]

    @property
    def crypto_cert(self) -> x509.Certificate:
        return self.certificate.to_cryptography()


@dataclass
class CertificateWrapper:
    certificate: x509.Certificate

    @classmethod
    def from_url(cls, url: str, timeout: float = 5) -> CertificateWrapper:
        # https://gist.github.com/brandond/f3d28734a40c49833176207b17a44786
        # https://gist.github.com/gdamjan/55a8b9eec6cf7b771f92021d93b87b2c
        bits = urlparse(url)
        hostname, _, port = bits.netloc.partition(":")
        port = port or "443"

        ssl_info = cls.fetch_certificate(hostname, int(port))

        return cls(certificate=ssl_info.crypto_cert)

    @staticmethod
    def fetch_certificate(hostname: str, port: int, timeout: float = 5) -> SSLInfo:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            ctx = SSL.Context(SSL.SSLv23_METHOD)  # most compatible
            ctx.check_hostname = False
            ctx.verify_mode = SSL.VERIFY_NONE

            with closing(SSL.Connection(ctx, sock)) as sock_ssl:
                # Workaround for timeout and OpenSSL.SSL.WantReadError
                # https://github.com/pyca/pyopenssl/issues/168
                sock_ssl.setblocking(1)

                sock_ssl.set_connect_state()
                hostname_idna = idna.encode(hostname)
                sock_ssl.set_tlsext_host_name(hostname_idna)

                sock_ssl.do_handshake()
                cert: crypto.X509 = sock_ssl.get_peer_certificate()
                chain: List[crypto.X509] = sock_ssl.get_peer_cert_chain()

        ssl_info = SSLInfo(certificate=cert, chain=chain)

        return ssl_info

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
