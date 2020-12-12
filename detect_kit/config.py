from __future__ import annotations

from pathlib import Path
from typing import Optional, Sequence, Union

import yaml
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
    expected_name_servers: Optional[Sequence[str]]
    expected_registrar_name: Optional[str]


class DetectKitSettings(BaseModel):
    certificates: Optional[Sequence[CertificateCheck]]
    domains: Optional[Sequence[DomainCheck]]


class Settings(BaseModel):
    version: str
    detect_kit: DetectKitSettings

    @classmethod
    def from_config_file(cls, config_path: Union[Path, str]) -> Settings:
        with open(config_path) as f:
            raw_config = yaml.safe_load(f)

        settings = cls.parse_obj(raw_config)

        return settings
