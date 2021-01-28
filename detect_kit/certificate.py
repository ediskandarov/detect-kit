from __future__ import annotations

import platform
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
    chain: List[crypto.X509]

    @property
    def crypto_cert(self) -> x509.Certificate:
        return self.certificate.to_cryptography()


@dataclass
class CertificateWrapper:
    certificate: x509.Certificate
    ssl_info: SSLInfo

    @classmethod
    def from_url(cls, url: str, timeout: float = 5) -> CertificateWrapper:
        # https://gist.github.com/brandond/f3d28734a40c49833176207b17a44786
        # https://gist.github.com/gdamjan/55a8b9eec6cf7b771f92021d93b87b2c
        bits = urlparse(url)
        hostname, _, port = bits.netloc.partition(":")
        port = port or "443"

        ssl_info = cls.fetch_certificate(hostname, int(port), timeout=timeout)

        return cls(certificate=ssl_info.crypto_cert, ssl_info=ssl_info)

    @staticmethod
    def fetch_certificate(hostname: str, port: int, timeout: float) -> SSLInfo:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
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

    def verify(self) -> bool:
        # https://yothenberg.com/validate-x509-certificate-in-python.html
        # https://github.com/pyca/pyopenssl/pull/948/files
        store_ctx = crypto.X509StoreContext(
            self.get_x509_store(no_check_time=True),
            self.ssl_info.certificate,
            chain=self.ssl_info.chain,
        )

        is_valid = True
        try:
            store_ctx.verify_certificate()
        except crypto.X509StoreContextError:
            is_valid = False

        return is_valid

    def get_x509_store(self, no_check_time: bool = False) -> crypto.X509Store:
        store = crypto.X509Store()

        # Do not check certificate/CRL validity against current time
        # https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/include/openssl/x509_vfy.h#L241-L242
        X509_V_FLAG_NO_CHECK_TIME = 0x200000

        # store.add_cert(root_cert)
        store.load_locations(cafile=self.ca_file)

        if no_check_time:
            store.set_flags(X509_V_FLAG_NO_CHECK_TIME)

        return store

    @property
    def ca_file(self) -> str:
        macOS_CA_FILE = "/etc/ssl/cert.pem"
        ubuntu_CA_FILE = "/etc/ssl/certs/ca-certificates.crt"

        system = platform.system()
        if system == "Linux":
            return ubuntu_CA_FILE
        elif system == "Darwin":
            return macOS_CA_FILE
        else:
            raise RuntimeError("Uncompatible system")
