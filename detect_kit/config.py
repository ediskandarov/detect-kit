from typing import Optional, Sequence

from pydantic import BaseModel, Field, HttpUrl


class CertificateCheck(BaseModel):
    site: HttpUrl
    # Additional sites that certificate should work for
    should_match_sites: Optional[Sequence[HttpUrl]]
    expiration_threshold_days: Optional[int] = Field(None, gt=0, le=365)
    expiration_threshold_relative: Optional[int] = Field(None, gt=0, le=100)
    expected_issuer_organisation_name: Optional[str]


class DomainCheck(BaseModel):
    domain: str
    expiration_threshold_days: Optional[int] = Field(None, gt=0, le=365)
    expiration_threshold_relative: Optional[int] = Field(None, gt=0, le=100)
    expected_name_servers: Optional[str]
    expected_registrar_name: Optional[str]


class Settings(BaseModel):
    version: int
    certificates: Optional[Sequence[CertificateCheck]]
    domains: Optional[Sequence[DomainCheck]]
