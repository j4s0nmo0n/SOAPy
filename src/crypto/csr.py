"""PKCS#10 CSR builder for AD CS certificate enrollment.

See design doc §3.3 "Extensions critiques pour ESC4":
  * SAN(otherName, OID 1.3.6.1.4.1.311.20.2.3 = Microsoft UPN) with the
    UPN encoded as a DER UTF8String. Client-side injection of the SID
    extension (1.3.6.1.4.1.311.25.2) is NOT done here — Win2025 CAs
    inject it themselves under KB5014754 Full Enforcement.
  * EKU with Client Authentication (OID 1.3.6.1.5.5.7.3.2), the only
    EKU needed for PKINIT.

See §4.3 for the API shape:
  ``build_csr(upn, cn=None, key_size=2048) -> (csr_der, private_key)``.
The private key is kept as a live ``RSAPrivateKey`` so Phase D can bundle
it with the issued certificate via
``cryptography.hazmat.primitives.serialization.pkcs12``.
"""

from __future__ import annotations

from typing import Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509.oid import NameOID

UPN_OID = x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")
EKU_CLIENT_AUTH_OID = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.2")
# szOID_ENROLL_CERTTYPE_EXTENSION — carries the template short name as a
# DER BMPString. The Enterprise CA policy module rejects enrollment via
# MS-WSTEP without this extension (0x80094801) even when AdditionalContext
# names the template OID in the SOAP envelope.
CERT_TEMPLATE_NAME_OID = x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2")

_UTF8STRING_TAG = 0x0C
_BMPSTRING_TAG = 0x1E


def _der_utf8string(s: str) -> bytes:
    """DER-encode ``s`` as an ASN.1 UTF8String (tag 0x0C)."""
    body = s.encode("utf-8")
    n = len(body)
    if n < 0x80:
        length = bytes([n])
    elif n < 0x100:
        length = bytes([0x81, n])
    elif n < 0x10000:
        length = bytes([0x82, n >> 8, n & 0xFF])
    else:
        raise ValueError(f"UTF8String too long for CSR SAN: {n} bytes")
    return bytes([_UTF8STRING_TAG]) + length + body


def _der_bmpstring(s: str) -> bytes:
    """DER-encode ``s`` as an ASN.1 BMPString (tag 0x1E, UTF-16 big-endian)."""
    body = s.encode("utf-16-be")
    n = len(body)
    if n < 0x80:
        length = bytes([n])
    elif n < 0x100:
        length = bytes([0x81, n])
    elif n < 0x10000:
        length = bytes([0x82, n >> 8, n & 0xFF])
    else:
        raise ValueError(f"BMPString too long for CSR CT extension: {n} bytes")
    return bytes([_BMPSTRING_TAG]) + length + body


def build_csr(
    upn: str,
    cn: Optional[str] = None,
    key_size: int = 2048,
    template_name: Optional[str] = None,
) -> Tuple[bytes, RSAPrivateKey]:
    """Build a PKCS#10 CSR with SAN(otherName=UPN) and EKU(ClientAuth).

    Returns ``(csr_der, private_key)``. If ``cn`` is omitted, derive it from
    ``upn`` (local part before ``@``, or the full UPN if there is no ``@``),
    mirroring certipy's default so PFXs produced by both tools stay visually
    comparable.

    When ``template_name`` is provided, embed the Microsoft Certificate
    Template Name extension (OID 1.3.6.1.4.1.311.20.2, BMPString). Required
    for MS-WSTEP enrollment against an Enterprise CA — see Phase E lab
    findings and the companion note in ``cert_enroll_wstep``.
    """
    if cn is None:
        cn = upn.split("@", 1)[0] if "@" in upn else upn

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    )
    builder = builder.add_extension(
        x509.SubjectAlternativeName(
            [x509.OtherName(UPN_OID, _der_utf8string(upn))]
        ),
        critical=False,
    )
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([EKU_CLIENT_AUTH_OID]),
        critical=False,
    )
    if template_name:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                CERT_TEMPLATE_NAME_OID, _der_bmpstring(template_name)
            ),
            critical=False,
        )
    csr = builder.sign(private_key, hashes.SHA256())
    csr_der = csr.public_bytes(serialization.Encoding.DER)
    return csr_der, private_key
