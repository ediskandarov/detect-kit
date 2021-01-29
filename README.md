# Overview

Detect Kit is a security framework for embedding into CI.

## Features

* Certificate checks
  * expiration
  * hostname match
  * issuer organisation name
  * certificate trust chain verification
* Domain checks
  * expiration
  * registrar name
  * name servers

## Error codes

| Code | Example Message |
|------|-----------------|
| C101 | `domain` certificate has expired |
| C102 | `domain` certificate does not match hostname |
| C103 | `domain` certificate does not match issuer |
| C104 | `domain` certificate fails trust chain verification |
| | |
| D101 | `domain` registration has expired |
| D102 | `domain` registrar name does not match |
| D103 | `domain` name servers does not match |
