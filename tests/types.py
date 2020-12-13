from typing import Callable

from whois import WhoisEntry

from detect_kit.certificate import CertificateWrapper
from detect_kit.config import CertificateCheck, DomainCheck

WhoisFactory = Callable[[DomainCheck], WhoisEntry]
CertificateFactory = Callable[[CertificateCheck], CertificateWrapper]
