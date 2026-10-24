# Changelog

All notable changes to this project are documented in this file. The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `--list-policies-ws` primitive calling MS-XCEP `GetPolicies` over HTTPS, with Kerberos authentication from the operator's ccache and `tls-server-end-point` channel binding (RFC 5929). Parses the response into a dataclass exposing templates, OIDs, CA bundle (chain + URIs) and the OID reference table.
- `--enroll-ws` primitive calling MS-WSTEP `RequestSecurityToken` over HTTPS. Chains `GetPolicies` → CSR build → `RequestSecurityToken` → PKCS#12 export. The resulting PFX is written with mode `0600`, bundles the CA chain when MS-XCEP exposes it, and is directly consumable by `certipy auth` or any PKINIT client.
- `src.crypto.csr.build_csr(upn, cn=None, key_size=2048, template_name=None)` helper that produces a PKCS#10 CSR with `SubjectAlternativeName(otherName=UPN, OID 1.3.6.1.4.1.311.20.2.3)`, `ExtendedKeyUsage(ClientAuthentication, OID 1.3.6.1.5.5.7.3.2)` and, when `template_name` is given, `szOID_ENROLL_CERTTYPE_EXTENSION` (OID `1.3.6.1.4.1.311.20.2`) carrying the template short name as a DER `BMPString`.
- CLI flags under a new `WS-Trust enrollment (MS-XCEP + MS-WSTEP)` argparse group: `--list-policies-ws`, `--enroll-ws`, `--cep-url`, `--ces-url`, `--ca`, `--template`, `--upn`, `--out`, `--insecure-ssl`.
- Unit tests covering CSR generation (SAN UPN, EKU, CT extension), MS-XCEP response parsing (templates, malformed-policy skip, SSL error surfacing), MS-WSTEP envelope building and the full enrollment orchestration against mocked `GetPolicies` + `RequestSecurityToken`.
- README section "Certificate enrollment via WS-Trust (MS-WSTEP)" documenting prerequisites, usage, the ESC4 full-SOAP chain, the KB5014754 interaction, and the deviations table recording what Windows Server 2025 CES actually accepts versus the canonical specifications.

### Fixed

- Note that the MS-WSTEP envelope uses the Microsoft-specific URIs for `wsa:Action`, `wst:TokenType` and `wsse:BinarySecurityToken` (`ValueType`, `EncodingType`) rather than the canonical OASIS WS-Trust 1.3 / WSS X.509 Token Profile URIs — the latter are rejected by WCF with "The action is invalid." / "The Token Type is invalid." / "The EncodingType is invalid." / "The ValueType of BinarySecurityToken is invalid." See the README deviations table.

### Dependencies

- Added `requests ^2.32.0` and `requests-gssapi ^1.4.0` as runtime dependencies in `pyproject.toml`. `cryptography` was already pulled in transitively through `impacket`.
