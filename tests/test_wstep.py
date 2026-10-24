"""Unit tests for ``src.cert_enroll_wstep``.

Covers design doc §3.2 (RST envelope), §4.3 (API shape), §6 (orchestration
PFX export) and the §7.1 test plan. No lab, no network — ``requests.post``
and the XCEP layer are monkeypatched.
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from base64 import b64encode
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from src import cert_enroll_wstep
from src.cert_enroll_wstep import (
    AC_NS,
    WSA_NS,
    WSSE_NS,
    WST_NS,
    WSTEP_ACTION,
    build_rst_request,
    parse_rstr_response,
)
from src.cert_enroll_xcep import CA, GetPoliciesResult, Template


# ---------------------------------------------------------------------------
# RST envelope
# ---------------------------------------------------------------------------


def test_wstep_build_rst_envelope():
    msg_id = "cafebabe-cafe-babe-cafe-babecafebabe"
    url = "https://dc-curse.jjk.local/jjk-CA_CES_Kerberos/service.svc/CES"
    csr_der = b"\x30\x82\x00\x10FAKECSRPAYLOAD!!"
    template_oid = "1.3.6.1.4.1.311.21.8.1.3"

    body = build_rst_request(url, csr_der, template_oid, msg_id=msg_id)
    root = ET.fromstring(body)

    action = root.find(f".//{{{WSA_NS}}}Action")
    assert action is not None and action.text == WSTEP_ACTION

    msg_id_elem = root.find(f".//{{{WSA_NS}}}MessageID")
    assert msg_id_elem is not None and msg_id_elem.text == f"urn:uuid:{msg_id}"

    to_elem = root.find(f".//{{{WSA_NS}}}To")
    assert to_elem is not None and to_elem.text == url

    token_type = root.find(f".//{{{WST_NS}}}TokenType")
    assert token_type is not None
    assert token_type.text.endswith("x509-token-profile-1.0#X509v3")

    request_type = root.find(f".//{{{WST_NS}}}RequestType")
    assert request_type is not None
    assert request_type.text == "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue"

    bst = root.find(f".//{{{WSSE_NS}}}BinarySecurityToken")
    assert bst is not None
    assert bst.get("ValueType", "").endswith("#PKCS10")
    assert bst.text == b64encode(csr_der).decode("ascii")

    # The template routing lives in the CSR's CT name extension — see Phase
    # E lab findings. The envelope must NOT carry AdditionalContext (adding
    # it triggers "The attributes are invalid" on the WCF endpoint).
    assert root.find(f".//{{{AC_NS}}}AdditionalContext") is None


# ---------------------------------------------------------------------------
# RSTR parse
# ---------------------------------------------------------------------------


_RSTR_SUCCESS_TMPL = """<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
            xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
  <s:Body>
    <wst:RequestSecurityTokenResponseCollection>
      <wst:RequestSecurityTokenResponse>
        <wst:TokenType>http://schemas.microsoft.com/5.0.0.0/ConfigurationServices/Enrollments/ClientCertificateEnrollment.wsdl</wst:TokenType>
        <wst:DispositionMessage>Issued</wst:DispositionMessage>
        <wst:RequestedSecurityToken>
          <wsse:BinarySecurityToken ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
                                     EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{cert_b64}</wsse:BinarySecurityToken>
        </wst:RequestedSecurityToken>
      </wst:RequestSecurityTokenResponse>
    </wst:RequestSecurityTokenResponseCollection>
  </s:Body>
</s:Envelope>
"""


_RSTR_FAULT = """<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <s:Fault>
      <s:Code><s:Value>s:Receiver</s:Value></s:Code>
      <s:Reason><s:Text xml:lang="en-US">The permissions on this certificate template do not allow the current user to enroll for this type of certificate.</s:Text></s:Reason>
    </s:Fault>
  </s:Body>
</s:Envelope>
"""


def test_wstep_parse_response_success():
    payload = b"\x11\x22\x33\x44\x55 fake cert DER bytes"
    xml = _RSTR_SUCCESS_TMPL.format(cert_b64=b64encode(payload).decode("ascii"))
    cert_der = parse_rstr_response(xml.encode("utf-8"))
    assert cert_der == payload


def test_wstep_parse_response_fault():
    with pytest.raises(RuntimeError) as excinfo:
        parse_rstr_response(_RSTR_FAULT.encode("utf-8"))
    msg = str(excinfo.value)
    assert "SOAP Fault" in msg
    assert "do not allow the current user to enroll" in msg


# ---------------------------------------------------------------------------
# Orchestration (template not found + integration)
# ---------------------------------------------------------------------------


def _fake_policies_with(template_name: str, template_oid: str = "1.3.6.1.4.1.311.21.8.1.3") -> GetPoliciesResult:
    result = GetPoliciesResult(policy_id="{TEST-POLICY-ID}")
    result.templates[template_name] = Template(
        name=template_name,
        oid=template_oid,
        template_oid_ref=1,
        cas=[1],
        min_key_length=2048,
    )
    result.cas[1] = CA(reference_id=1)  # no CA cert — tested path (log warning)
    return result


def test_wstep_cmd_enroll_template_not_found(monkeypatch, tmp_path, caplog):
    monkeypatch.setattr(cert_enroll_wstep, "kerberos_auth", lambda: None)
    monkeypatch.setattr(
        cert_enroll_wstep,
        "get_policies",
        lambda *a, **kw: _fake_policies_with("User"),
    )

    out = tmp_path / "nope.pfx"
    with caplog.at_level(logging.CRITICAL):
        with pytest.raises(SystemExit) as excinfo:
            cert_enroll_wstep.run_enroll(
                remote_name="dc-curse.jjk.local",
                ces_url="https://dc/CES",
                cep_url="https://dc/CEP",
                ca_name=None,
                template_name="MissingTemplate",
                upn="yuji@jjk.local",
                out_path=str(out),
                insecure_ssl=True,
            )
    assert excinfo.value.code == 1
    assert not out.exists()
    assert any(
        "MissingTemplate" in rec.getMessage() and "not found" in rec.getMessage()
        for rec in caplog.records
    )


def _issue_fake_cert_from_csr(csr_der: bytes) -> bytes:
    """Simulate what a CA would return: a cert carrying the CSR's pubkey + extensions."""
    csr = x509.load_der_x509_csr(csr_der)
    issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "jjk-CA")]))
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(hours=1))
        .not_valid_after(now + timedelta(days=1))
    )
    for ext in csr.extensions:
        builder = builder.add_extension(ext.value, critical=ext.critical)
    cert = builder.sign(issuer_key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


def test_wstep_cmd_enroll_integration(monkeypatch, tmp_path, capsys):
    captured_csr: dict = {}

    def fake_request_cert(host, ca_name, template_oid, csr_der, auth, verify_ssl=True, timeout=60.0):
        captured_csr["der"] = csr_der
        captured_csr["template_oid"] = template_oid
        captured_csr["host"] = host
        return _issue_fake_cert_from_csr(csr_der)

    monkeypatch.setattr(cert_enroll_wstep, "kerberos_auth", lambda: None)
    monkeypatch.setattr(
        cert_enroll_wstep,
        "get_policies",
        lambda *a, **kw: _fake_policies_with("ESC4Test"),
    )
    monkeypatch.setattr(cert_enroll_wstep, "request_cert", fake_request_cert)

    out = tmp_path / "esc4.pfx"
    cert_enroll_wstep.run_enroll(
        remote_name="dc-curse.jjk.local",
        ces_url=None,
        cep_url=None,
        ca_name="jjk-CA",
        template_name="ESC4Test",
        upn="administrator@jjk.local",
        out_path=str(out),
        insecure_ssl=True,
    )

    # URL derivation hit the default CES/CEP builders.
    assert captured_csr["host"].endswith("/jjk-CA_CES_Kerberos/service.svc/CES")
    assert captured_csr["template_oid"] == "1.3.6.1.4.1.311.21.8.1.3"

    assert out.exists()
    assert (out.stat().st_mode & 0o777) == 0o600

    key, cert, cas = pkcs12.load_key_and_certificates(out.read_bytes(), None)
    assert key is not None
    assert cert is not None
    assert cas == []  # no CA cert in XCEP response → PFX has end cert only

    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert cn_attrs and cn_attrs[0].value == "administrator"

    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert x509.ObjectIdentifier("1.3.6.1.5.5.7.3.2") in list(eku)

    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    other_names = san.get_values_for_type(x509.OtherName)
    assert other_names and other_names[0].type_id == x509.ObjectIdentifier(
        "1.3.6.1.4.1.311.20.2.3"
    )

    stdout = capsys.readouterr().out
    assert "Certificate enrolled" in stdout
    assert str(out) in stdout
    assert "certipy auth -pfx" in stdout
