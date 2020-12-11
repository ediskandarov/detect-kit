from __future__ import annotations

from datetime import datetime
import socket
import ssl
from urllib.parse import urlparse

from pydantic import BaseModel, Field, validator
from typing import List, Tuple, Optional
from tenacity import retry, stop_after_attempt


class CertificateIssuerModel(BaseModel):
    country_name: Optional[str] = Field(None, alias="countryName")
    organization_name: Optional[str] = Field(None, alias="organizationName")
    organizational_unit_name: Optional[str] = Field(
        None, alias="organizationalUnitName"
    )
    common_name: Optional[str] = Field(None, alias="commonName")

    class Config:
        allow_population_by_field_name = False


class CertificateSubjectModel(BaseModel):
    common_name: Optional[str] = Field(None, alias="commonName")
    organizational_unit_name: Optional[str] = Field(
        None, alias="organizationalUnitName"
    )
    organization_name: Optional[str] = Field(None, alias="organizationName")
    locality_name: Optional[str] = Field(None, alias="localityName")
    state_or_province_name: Optional[str] = Field(None, alias="stateOrProvinceName")
    country_name: Optional[str] = Field(None, alias="countryName")

    class Config:
        allow_population_by_field_name = False


class CertificateModel(BaseModel):
    issuer: CertificateIssuerModel
    subject: CertificateSubjectModel
    serial_number: Optional[str] = Field(None, alias="serialNumber")
    subject_alt_name: Optional[List[Tuple[str, str]]] = Field(
        None, alias="subjectAltName"
    )
    not_before: Optional[datetime] = Field(None, alias="notBefore")
    not_after: Optional[datetime] = Field(None, alias="notAfter")

    class Config:
        allow_population_by_field_name = False

    @validator("issuer", pre=True)
    def parse_issuer(cls, value) -> Optional[CertificateIssuerModel]:
        data = {k: v for ((k, v),) in value}
        issuer = CertificateIssuerModel.parse_obj(data)
        return issuer

    @validator("subject", pre=True)
    def parse_subject(cls, value) -> Optional[CertificateSubjectModel]:
        data = {k: v for ((k, v),) in value}
        subject = CertificateSubjectModel.parse_obj(data)
        return subject

    @validator("not_before", pre=True)
    def parse_not_before(cls, value) -> Optional[datetime]:
        if isinstance(value, str):
            timestamp = ssl.cert_time_to_seconds(value)
            not_before = datetime.utcfromtimestamp(timestamp)
            return not_before

    @validator("not_after", pre=True)
    def parse_not_after(cls, value) -> Optional[datetime]:
        if isinstance(value, str):
            timestamp = ssl.cert_time_to_seconds(value)
            not_after = datetime.utcfromtimestamp(timestamp)
            return not_after

    def match_hostname(self, hostname: str) -> bool:
        cert = {
            "subject": ((("commonName", self.subject.common_name),),),
        }

        if self.subject_alt_name is not None:
            cert["subjectAltName"] = tuple(item for item in self.subject_alt_name)

        try:
            ssl.match_hostname(cert, hostname)
        except ssl.CertificateError:
            return False
        else:
            return True

    @classmethod
    @retry(reraise=True, stop=stop_after_attempt(3))
    def from_url(cls, url: str, timeout: float = 5) -> CertificateModel:
        bits = urlparse(url)
        hostname, _, port = bits.netloc.partition(":")
        # if port is provided - cast value to int, otherwise use default https port number
        port = int(port) if port else 443

        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        obj = cls.parse_obj(cert)
        return obj
