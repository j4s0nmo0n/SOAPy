"""Unit tests for ``src.crypto.csr.build_csr``.

Covers design doc §3.3 extensions (SAN otherName UPN + EKU Client Auth)
and the §4.3 API contract. Phase B — no network, no lab.
"""

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509.oid import NameOID

from src.crypto.csr import EKU_CLIENT_AUTH_OID, UPN_OID, build_csr


def _get_upn_from_san(csr: x509.CertificateSigningRequest) -> str:
    """Pull the UPN out of the SAN otherName entry (DER UTF8String)."""
    san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    other_names = san_ext.value.get_values_for_type(x509.OtherName)
    assert other_names, "SAN has no otherName entry"
    on = other_names[0]
    assert on.type_id == UPN_OID
    data = on.value
    assert data[0] == 0x0C, "SAN otherName value is not an ASN.1 UTF8String"
    first_len = data[1]
    if first_len & 0x80 == 0:
        length = first_len
        start = 2
    else:
        n_len = first_len & 0x7F
        length = int.from_bytes(data[2:2 + n_len], "big")
        start = 2 + n_len
    return data[start:start + length].decode("utf-8")


def test_build_csr_default():
    upn = "yuji@jjk.local"
    csr_der, private_key = build_csr(upn)

    assert isinstance(private_key, RSAPrivateKey)
    assert private_key.key_size == 2048

    csr = x509.load_der_x509_csr(csr_der)
    assert csr.is_signature_valid

    cn_attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert len(cn_attrs) == 1
    assert cn_attrs[0].value == "yuji"

    assert _get_upn_from_san(csr) == upn


def test_build_csr_eku():
    csr_der, _ = build_csr("yuji@jjk.local")
    csr = x509.load_der_x509_csr(csr_der)
    eku_ext = csr.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    assert EKU_CLIENT_AUTH_OID in list(eku_ext.value)


def test_build_csr_custom_cn():
    upn = "administrator@jjk.local"
    cn = "totally_different_cn"
    csr_der, _ = build_csr(upn, cn=cn)

    csr = x509.load_der_x509_csr(csr_der)
    cn_attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert len(cn_attrs) == 1
    assert cn_attrs[0].value == cn

    assert _get_upn_from_san(csr) == upn


def test_build_csr_key_size():
    csr_der, private_key = build_csr("yuji@jjk.local", key_size=4096)
    assert private_key.key_size == 4096

    csr = x509.load_der_x509_csr(csr_der)
    assert csr.public_key().key_size == 4096


def test_build_csr_with_template_name_adds_ct_extension():
    """CT name extension (BMPString) is required by Enterprise CA policy module."""
    from src.crypto.csr import CERT_TEMPLATE_NAME_OID

    csr_der, _ = build_csr("yuji@jjk.local", template_name="ESC4Test")
    csr = x509.load_der_x509_csr(csr_der)

    ct_ext = next(
        (e for e in csr.extensions if e.oid == CERT_TEMPLATE_NAME_OID), None
    )
    assert ct_ext is not None, "CT name extension missing from CSR"

    raw = ct_ext.value.value  # UnrecognizedExtension inner DER bytes
    assert raw[0] == 0x1E, "CT value is not a BMPString (tag 0x1E)"
    # Decode short-form length BMPString and compare
    length = raw[1]
    assert length < 0x80, "unexpected long-form length for short template name"
    decoded = raw[2:2 + length].decode("utf-16-be")
    assert decoded == "ESC4Test"


def test_build_csr_without_template_name_omits_ct_extension():
    from src.crypto.csr import CERT_TEMPLATE_NAME_OID

    csr_der, _ = build_csr("yuji@jjk.local")
    csr = x509.load_der_x509_csr(csr_der)
    assert not any(e.oid == CERT_TEMPLATE_NAME_OID for e in csr.extensions)
