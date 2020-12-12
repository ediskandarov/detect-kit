from typing import Callable

from whois import WhoisEntry

from detect_kit.config import CertificateCheck, DomainCheck
from detect_kit.models import CertificateModel

WhoisFactory = Callable[[DomainCheck], WhoisEntry]
CertificateFactory = Callable[[CertificateCheck], CertificateModel]
