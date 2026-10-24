"""Unit tests for ``src.cert_enroll_xcep``.

Covers design doc §3.1 (request envelope) and the §7.1 test plan:
parse of a synthetic GetPoliciesResponse, graceful skip of a malformed
policy, canonical shape of the built request, and lab-friendly SSL error.
No lab, no network.
"""

import logging
import xml.etree.ElementTree as ET

import pytest
import requests

from src import cert_enroll_xcep
from src.cert_enroll_xcep import (
    WSA_NS,
    XCEP_ACTION,
    XCEP_NS,
    build_get_policies_request,
    get_policies,
    parse_get_policies_response,
)


SAMPLE_RESPONSE_XML = """<?xml version="1.0" encoding="utf-8"?>
<GetPoliciesResponse xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy">
  <response>
    <policyID>{A1B2C3D4-1111-2222-3333-444455556666}</policyID>
    <policyFriendlyName>JJK Enrollment Policy</policyFriendlyName>
    <nextUpdateHours>8</nextUpdateHours>
    <policiesNotChanged>false</policiesNotChanged>
    <policies>
      <policy>
        <policyOIDReference>1</policyOIDReference>
        <cAs><cAReference>1</cAReference></cAs>
        <attributes>
          <commonName>User</commonName>
          <privateKeyAttributes><minimalKeyLength>2048</minimalKeyLength></privateKeyAttributes>
          <revision><majorRevision>100</majorRevision><minorRevision>2</minorRevision></revision>
          <hashAlgorithmOIDReference>10</hashAlgorithmOIDReference>
        </attributes>
      </policy>
      <policy>
        <policyOIDReference>2</policyOIDReference>
        <cAs><cAReference>1</cAReference></cAs>
        <attributes>
          <commonName>Machine</commonName>
          <privateKeyAttributes><minimalKeyLength>2048</minimalKeyLength></privateKeyAttributes>
          <revision><majorRevision>100</majorRevision><minorRevision>2</minorRevision></revision>
          <hashAlgorithmOIDReference>10</hashAlgorithmOIDReference>
        </attributes>
      </policy>
      <policy>
        <policyOIDReference>3</policyOIDReference>
        <cAs><cAReference>1</cAReference></cAs>
        <attributes>
          <commonName>ESC4Test</commonName>
          <privateKeyAttributes><minimalKeyLength>4096</minimalKeyLength></privateKeyAttributes>
          <revision><majorRevision>101</majorRevision><minorRevision>0</minorRevision></revision>
          <hashAlgorithmOIDReference>10</hashAlgorithmOIDReference>
        </attributes>
      </policy>
    </policies>
  </response>
  <cAs>
    <cA>
      <uris>
        <cAURI>
          <clientAuthentication>2</clientAuthentication>
          <uri>https://dc-curse.jjk.local/jjk-CA_CES_Kerberos/service.svc/CES</uri>
          <priority>1</priority>
          <renewalOnly>false</renewalOnly>
        </cAURI>
      </uris>
      <certificate></certificate>
      <enrollPermission>true</enrollPermission>
      <cAReferenceID>1</cAReferenceID>
    </cA>
  </cAs>
  <oIDs>
    <oID>
      <value>1.3.6.1.4.1.311.21.8.1.1</value>
      <group>3</group>
      <oIDReferenceID>1</oIDReferenceID>
      <defaultName>User</defaultName>
    </oID>
    <oID>
      <value>1.3.6.1.4.1.311.21.8.1.2</value>
      <group>3</group>
      <oIDReferenceID>2</oIDReferenceID>
      <defaultName>Machine</defaultName>
    </oID>
    <oID>
      <value>1.3.6.1.4.1.311.21.8.1.3</value>
      <group>3</group>
      <oIDReferenceID>3</oIDReferenceID>
      <defaultName>ESC4Test</defaultName>
    </oID>
    <oID>
      <value>2.16.840.1.101.3.4.2.1</value>
      <group>7</group>
      <oIDReferenceID>10</oIDReferenceID>
      <defaultName>SHA256</defaultName>
    </oID>
  </oIDs>
</GetPoliciesResponse>
"""


# Same as SAMPLE_RESPONSE_XML with an extra <policy> whose <commonName>
# is missing — the parser must skip just that one and still return the others.
MALFORMED_RESPONSE_XML = SAMPLE_RESPONSE_XML.replace(
    "</policies>",
    """<policy>
        <policyOIDReference>99</policyOIDReference>
        <cAs><cAReference>1</cAReference></cAs>
        <attributes>
          <privateKeyAttributes><minimalKeyLength>2048</minimalKeyLength></privateKeyAttributes>
          <revision><majorRevision>1</majorRevision><minorRevision>0</minorRevision></revision>
        </attributes>
      </policy>
    </policies>""",
)


def test_xcep_parse_minimal():
    result = parse_get_policies_response(SAMPLE_RESPONSE_XML.encode("utf-8"))

    assert result.policy_id == "{A1B2C3D4-1111-2222-3333-444455556666}"

    assert set(result.templates) == {"User", "Machine", "ESC4Test"}
    assert result.templates["User"].oid == "1.3.6.1.4.1.311.21.8.1.1"
    assert result.templates["User"].min_key_length == 2048
    assert result.templates["User"].cas == [1]
    assert result.templates["ESC4Test"].min_key_length == 4096
    assert result.templates["ESC4Test"].revision == "101.0"
    assert result.templates["User"].hash_algos == ["2.16.840.1.101.3.4.2.1"]

    assert 1 in result.cas
    assert result.cas[1].uris == [
        "https://dc-curse.jjk.local/jjk-CA_CES_Kerberos/service.svc/CES"
    ]
    assert result.cas[1].cert_der is None  # empty <certificate>

    assert result.oids["1.3.6.1.4.1.311.21.8.1.1"] == "User"
    assert result.oids["2.16.840.1.101.3.4.2.1"] == "SHA256"


def test_xcep_parse_malformed_skip(caplog):
    with caplog.at_level(logging.WARNING, logger="root"):
        result = parse_get_policies_response(MALFORMED_RESPONSE_XML.encode("utf-8"))

    assert set(result.templates) == {"User", "Machine", "ESC4Test"}
    assert any(
        "Skipping malformed policy" in rec.getMessage() for rec in caplog.records
    ), f"expected a warning log, got: {[r.getMessage() for r in caplog.records]}"


def test_xcep_build_request():
    msg_id = "deadbeef-dead-beef-dead-beefdeadbeef"
    url = "https://dc-curse.jjk.local/ADPolicyProvider_CEP_Kerberos/service.svc/CEP"
    body = build_get_policies_request(url, msg_id=msg_id)

    root = ET.fromstring(body)

    action = root.find(f".//{{{WSA_NS}}}Action")
    assert action is not None and action.text == XCEP_ACTION

    msg_id_elem = root.find(f".//{{{WSA_NS}}}MessageID")
    assert msg_id_elem is not None
    assert msg_id_elem.text == f"urn:uuid:{msg_id}"

    to_elem = root.find(f".//{{{WSA_NS}}}To")
    assert to_elem is not None and to_elem.text == url

    getpol = root.find(f".//{{{XCEP_NS}}}GetPolicies")
    assert getpol is not None


def test_xcep_ssl_error(monkeypatch):
    def fake_post(*args, **kwargs):
        raise requests.exceptions.SSLError("certificate verify failed")

    monkeypatch.setattr(cert_enroll_xcep.requests, "post", fake_post)

    with pytest.raises(ConnectionError) as excinfo:
        get_policies("https://example.invalid/CEP", auth=None)

    assert "--insecure-ssl" in str(excinfo.value)
