"""Unit tests for the regex-based MS-ADCAP response parsers.

All XML fixtures are anonymised: example.local / DC-01 / acme.
"""

import unittest
from unittest.mock import MagicMock

from src import adcap


def _wrap_envelope(body_xml: str) -> str:
    """Wrap payload XML in a minimal SOAP envelope — mirrors the shape
    the DC returns on the wire so the regex parsers see realistic input.
    """
    return (
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
        '<s:Header/>'
        f'<s:Body>{body_xml}</s:Body>'
        '</s:Envelope>'
    )


def _fake_client(resp_xml: str) -> adcap.ADWSConnect:
    """Build an ADWSConnect stand-in: just enough surface for the
    adcap.* functions to send/recv without touching the network.
    """
    client = MagicMock(spec=adcap.ADWSConnect)
    client._fqdn = "dc-01.example.local"
    client._nmf = MagicMock()
    client._nmf.recv.return_value = resp_xml
    return client


class ScalarArrayHelpersTests(unittest.TestCase):
    """Direct exercise of the factored _scalar / _array helpers so the
    regex contracts are visible and locked down (no reliance on a full
    primitive to notice a regression)."""

    def test_scalar_matches_namespaced_tag(self):
        xml = '<ns0:Name xmlns:ns0="urn:x">example.local</ns0:Name>'
        self.assertEqual(adcap._scalar(xml, "Name"), "example.local")

    def test_scalar_returns_none_on_xsi_nil(self):
        xml = '<ns0:ParentDomain xmlns:xsi="x" xsi:nil="true"/>'
        self.assertIsNone(adcap._scalar(xml, "ParentDomain"))

    def test_scalar_absent_returns_none(self):
        self.assertIsNone(adcap._scalar("<other/>", "Name"))

    def test_array_pulls_string_children_from_any_namespace(self):
        xml = (
            '<ns0:Domains>'
            '<b:string>a.example.local</b:string>'
            '<b:string>b.example.local</b:string>'
            '</ns0:Domains>'
        )
        self.assertEqual(
            adcap._array(xml, "Domains"),
            ["a.example.local", "b.example.local"],
        )

    def test_array_returns_none_on_nil(self):
        xml = '<ns0:Sites xsi:nil="true"/>'
        self.assertIsNone(adcap._array(xml, "Sites"))

    def test_array_returns_empty_on_present_but_empty_wrapper(self):
        xml = '<ns0:Sites></ns0:Sites>'
        self.assertEqual(adcap._array(xml, "Sites"), [])


class GetVersionTests(unittest.TestCase):

    def test_get_version_parses_three_scalars(self):
        resp = _wrap_envelope(
            '<ns0:GetVersionResponse xmlns:ns0="urn:x">'
            '<ns0:VersionMajor>10</ns0:VersionMajor>'
            '<ns0:VersionMinor>0</ns0:VersionMinor>'
            '<ns0:VersionString>6.3</ns0:VersionString>'
            '</ns0:GetVersionResponse>'
        )
        client = _fake_client(resp)
        result = adcap.get_version(client)
        self.assertEqual(result, {
            "version_major": 10,
            "version_minor": 0,
            "version_string": "6.3",
        })

    def test_get_version_sends_right_action(self):
        resp = _wrap_envelope(
            '<ns0:GetVersionResponse xmlns:ns0="urn:x">'
            '<ns0:VersionMajor>10</ns0:VersionMajor>'
            '<ns0:VersionMinor>0</ns0:VersionMinor>'
            '<ns0:VersionString>6.3</ns0:VersionString>'
            '</ns0:GetVersionResponse>'
        )
        client = _fake_client(resp)
        adcap.get_version(client)
        sent = client._nmf.send.call_args[0][0]
        self.assertIn("TopologyManagement/GetVersion", sent)
        self.assertIn("<ca:Server>ldap:389</ca:Server>", sent)
        self.assertIn("<ca:GetVersionRequest/>", sent)

    def test_get_version_tolerates_missing_fields(self):
        resp = _wrap_envelope('<ns0:GetVersionResponse xmlns:ns0="urn:x"/>')
        client = _fake_client(resp)
        result = adcap.get_version(client)
        self.assertEqual(result["version_major"], 0)
        self.assertEqual(result["version_minor"], 0)
        self.assertEqual(result["version_string"], "")


class GetADDomainTests(unittest.TestCase):

    def test_get_ad_domain_parses_arrays_scalars_and_nil(self):
        resp = _wrap_envelope(
            '<ns0:GetADDomainResponse xmlns:ns0="urn:x" xmlns:xsi="urn:xsi">'
            '<ns0:Domain>'
            '<ns0:AllowedDNSSuffixes xsi:nil="true"/>'
            '<ns0:AppliedGroupPolicies>'
            '<b:string>CN=Default Domain Policy,CN=Policies,CN=System,DC=example,DC=local</b:string>'
            '</ns0:AppliedGroupPolicies>'
            '<ns0:ChildDomains>'
            '<b:string>sub.example.local</b:string>'
            '</ns0:ChildDomains>'
            '<ns0:ComputersContainer>CN=Computers,DC=example,DC=local</ns0:ComputersContainer>'
            '<ns0:DeletedObjectsContainer>CN=Deleted Objects,DC=example,DC=local</ns0:DeletedObjectsContainer>'
            '<ns0:DistinguishedName>DC=example,DC=local</ns0:DistinguishedName>'
            '<ns0:DNSRoot>example.local</ns0:DNSRoot>'
            '<ns0:DomainControllersContainer>OU=Domain Controllers,DC=example,DC=local</ns0:DomainControllersContainer>'
            '<ns0:DomainMode>7</ns0:DomainMode>'
            '<ns0:DomainSID>S-1-5-21-1-2-3</ns0:DomainSID>'
            '<ns0:ForeignSecurityPrincipalsContainer>CN=ForeignSecurityPrincipals,DC=example,DC=local</ns0:ForeignSecurityPrincipalsContainer>'
            '<ns0:Forest>example.local</ns0:Forest>'
            '<ns0:InfrastructureMaster>DC-01.example.local</ns0:InfrastructureMaster>'
            '<ns0:LastLogonReplicationInterval xsi:nil="true"/>'
            '<ns0:LostAndFoundContainer>CN=LostAndFound,DC=example,DC=local</ns0:LostAndFoundContainer>'
            '<ns0:ManagedBy xsi:nil="true"/>'
            '<ns0:Name>example</ns0:Name>'
            '<ns0:NetBIOSName>EXAMPLE</ns0:NetBIOSName>'
            '<ns0:ObjectClass>domainDNS</ns0:ObjectClass>'
            '<ns0:ObjectGuid>abcdef12-3456-7890-abcd-ef1234567890</ns0:ObjectGuid>'
            '<ns0:ObjectTypes>'
            '<b:string>domainDNS</b:string>'
            '</ns0:ObjectTypes>'
            '<ns0:ParentDomain xsi:nil="true"/>'
            '<ns0:PDCEmulator>DC-01.example.local</ns0:PDCEmulator>'
            '<ns0:QuotasContainer>CN=NTDS Quotas,DC=example,DC=local</ns0:QuotasContainer>'
            '<ns0:ReadOnlyReplicaDirectoryServer xsi:nil="true"/>'
            '<ns0:ReferenceServer>DC-01.example.local</ns0:ReferenceServer>'
            '<ns0:ReplicaDirectoryServer>'
            '<b:string>DC-01.example.local</b:string>'
            '<b:string>DC-02.example.local</b:string>'
            '</ns0:ReplicaDirectoryServer>'
            '<ns0:RIDMaster>DC-01.example.local</ns0:RIDMaster>'
            '<ns0:SubordinateReferences>'
            '<b:string>DC=ForestDnsZones,DC=example,DC=local</b:string>'
            '</ns0:SubordinateReferences>'
            '<ns0:SystemsContainer>CN=System,DC=example,DC=local</ns0:SystemsContainer>'
            '<ns0:UsersContainer>CN=Users,DC=example,DC=local</ns0:UsersContainer>'
            '</ns0:Domain>'
            '</ns0:GetADDomainResponse>'
        )
        client = _fake_client(resp)
        result = adcap.get_ad_domain(client)

        # Scalars
        self.assertEqual(result["name"], "example")
        self.assertEqual(result["dns_root"], "example.local")
        self.assertEqual(result["net_bios_name"], "EXAMPLE")
        self.assertEqual(result["domain_sid"], "S-1-5-21-1-2-3")
        self.assertEqual(result["domain_mode"], 7)
        self.assertEqual(result["pdc_emulator"], "DC-01.example.local")
        self.assertEqual(result["rid_master"], "DC-01.example.local")
        self.assertEqual(result["infrastructure_master"], "DC-01.example.local")
        self.assertEqual(result["forest"], "example.local")

        # Arrays
        self.assertEqual(result["applied_group_policies"], [
            "CN=Default Domain Policy,CN=Policies,CN=System,DC=example,DC=local",
        ])
        self.assertEqual(result["child_domains"], ["sub.example.local"])
        self.assertEqual(result["replica_directory_server"], [
            "DC-01.example.local", "DC-02.example.local",
        ])
        self.assertEqual(result["subordinate_references"], [
            "DC=ForestDnsZones,DC=example,DC=local",
        ])
        self.assertEqual(result["object_types"], ["domainDNS"])

        # Nullable scalars (xsi:nil="true")
        self.assertIsNone(result["parent_domain"])
        self.assertIsNone(result["managed_by"])
        self.assertIsNone(result["last_logon_replication_interval"])

        # Nullable arrays (xsi:nil="true")
        self.assertIsNone(result["allowed_dns_suffixes"])
        self.assertIsNone(result["read_only_replica_directory_server"])

    def test_get_ad_domain_sends_identity_when_supplied(self):
        resp = _wrap_envelope(
            '<ns0:GetADDomainResponse xmlns:ns0="urn:x">'
            '<ns0:Domain><ns0:Name>example</ns0:Name></ns0:Domain>'
            '</ns0:GetADDomainResponse>'
        )
        client = _fake_client(resp)
        adcap.get_ad_domain(client, identity="example.local")
        sent = client._nmf.send.call_args[0][0]
        self.assertIn("TopologyManagement/GetADDomain", sent)
        self.assertIn("<ca:Identity>example.local</ca:Identity>", sent)

    def test_get_ad_domain_omits_identity_when_none(self):
        resp = _wrap_envelope(
            '<ns0:GetADDomainResponse xmlns:ns0="urn:x">'
            '<ns0:Domain><ns0:Name>example</ns0:Name></ns0:Domain>'
            '</ns0:GetADDomainResponse>'
        )
        client = _fake_client(resp)
        adcap.get_ad_domain(client)
        sent = client._nmf.send.call_args[0][0]
        self.assertNotIn("<ca:Identity>", sent)


class GetADDomainControllerTests(unittest.TestCase):

    def test_empty_ntds_settings_dn_raises_before_any_network_call(self):
        client = _fake_client("<unreachable/>")
        with self.assertRaises(ValueError):
            adcap.get_ad_domain_controller(client, [])
        client._nmf.send.assert_not_called()

    def test_body_wraps_each_dn_in_a_string_element(self):
        # No real DC fixture yet (first live request faults until the real
        # response is captured). Minimum valid-looking response so the
        # parser doesn't blow up.
        resp = _wrap_envelope(
            '<ns0:GetADDomainControllerResponse xmlns:ns0="urn:x">'
            '<ns0:DomainController><ns0:Name>DC-01</ns0:Name></ns0:DomainController>'
            '</ns0:GetADDomainControllerResponse>'
        )
        client = _fake_client(resp)
        adcap.get_ad_domain_controller(client, [
            "CN=NTDS Settings,CN=DC-01,CN=Servers,CN=Site1,CN=Sites,CN=Configuration,DC=example,DC=local",
            "CN=NTDS Settings,CN=DC-02,CN=Servers,CN=Site1,CN=Sites,CN=Configuration,DC=example,DC=local",
        ])
        sent = client._nmf.send.call_args[0][0]
        self.assertIn("TopologyManagement/GetADDomainController", sent)
        self.assertIn("<ca:NtdsSettingsDN", sent)
        self.assertIn(
            "<b:string>CN=NTDS Settings,CN=DC-01,CN=Servers,CN=Site1,CN=Sites,CN=Configuration,DC=example,DC=local</b:string>",
            sent,
        )
        self.assertIn(
            "<b:string>CN=NTDS Settings,CN=DC-02,CN=Servers,CN=Site1,CN=Sites,CN=Configuration,DC=example,DC=local</b:string>",
            sent,
        )

    def test_parse_dc_payload_classifies_scalars_arrays_and_nil(self):
        # Synthetic payload — real field names will be pinned down once a
        # live GetADDomainController succeeds in lab. The generic walker
        # must still classify shapes correctly regardless of names.
        resp = _wrap_envelope(
            '<ns0:GetADDomainControllerResponse xmlns:ns0="urn:x" xmlns:xsi="urn:xsi">'
            '<ns0:DomainController>'
            '<ns0:Name>DC-01</ns0:Name>'
            '<ns0:HostName>DC-01.example.local</ns0:HostName>'
            '<ns0:Site xsi:nil="true"/>'
            '<ns0:Roles>'
            '<b:string>PDCEmulator</b:string>'
            '<b:string>RIDMaster</b:string>'
            '</ns0:Roles>'
            '</ns0:DomainController>'
            '</ns0:GetADDomainControllerResponse>'
        )
        parsed = adcap._parse_dc_payload(resp)
        self.assertEqual(parsed["name"], "DC-01")
        self.assertEqual(parsed["host_name"], "DC-01.example.local")
        self.assertIsNone(parsed["site"])
        self.assertEqual(parsed["roles"], ["PDCEmulator", "RIDMaster"])

    def test_parse_dc_payload_flattens_operation_master_role_subelements(self):
        """OperationMasterRole wraps repeated typed children
        (<ActiveDirectoryOperationMasterRole>…</…>) rather than
        <string>. The generic walker must still extract them as a list,
        not keep the raw markup as a scalar (the pre-fix behaviour)."""
        resp = _wrap_envelope(
            '<ns0:GetADDomainControllerResponse xmlns:ns0="urn:x">'
            '<ns0:DomainController>'
            '<ns0:Name>DC-01</ns0:Name>'
            '<ns0:OperationMasterRole>'
            '<ns0:ActiveDirectoryOperationMasterRole>SchemaMaster</ns0:ActiveDirectoryOperationMasterRole>'
            '<ns0:ActiveDirectoryOperationMasterRole>DomainNamingMaster</ns0:ActiveDirectoryOperationMasterRole>'
            '<ns0:ActiveDirectoryOperationMasterRole>PDCEmulator</ns0:ActiveDirectoryOperationMasterRole>'
            '<ns0:ActiveDirectoryOperationMasterRole>RIDMaster</ns0:ActiveDirectoryOperationMasterRole>'
            '<ns0:ActiveDirectoryOperationMasterRole>InfrastructureMaster</ns0:ActiveDirectoryOperationMasterRole>'
            '</ns0:OperationMasterRole>'
            '</ns0:DomainController>'
            '</ns0:GetADDomainControllerResponse>'
        )
        parsed = adcap._parse_dc_payload(resp)
        self.assertEqual(
            parsed["operation_master_role"],
            ["SchemaMaster", "DomainNamingMaster",
             "PDCEmulator", "RIDMaster", "InfrastructureMaster"],
        )


class DecodeBinarySidTests(unittest.TestCase):

    def test_decodes_base64_binary_sid_to_canonical(self):
        # S-1-5-21-1687579186-3856638039-375210320 encoded as the server
        # ships it (xs:base64Binary over the wire).
        from base64 import b64encode
        from impacket.ldap.ldaptypes import LDAP_SID
        sid = LDAP_SID()
        sid.fromCanonical("S-1-5-21-1687579186-3856638039-375210320")
        wire = b64encode(sid.getData()).decode()
        self.assertEqual(
            adcap._decode_binary_sid_b64(wire),
            "S-1-5-21-1687579186-3856638039-375210320",
        )

    def test_passes_through_already_canonical_sid(self):
        # Fixtures and pre-decoded payloads use the dotted form; the
        # decoder MUST leave them untouched so tests stay deterministic.
        self.assertEqual(
            adcap._decode_binary_sid_b64("S-1-5-21-1-2-3"),
            "S-1-5-21-1-2-3",
        )

    def test_passes_through_empty_string(self):
        self.assertEqual(adcap._decode_binary_sid_b64(""), "")


class PascalToSnakeTests(unittest.TestCase):

    def test_simple_pascal(self):
        self.assertEqual(adcap._pascal_to_snake("Name"), "name")

    def test_two_word_pascal(self):
        self.assertEqual(adcap._pascal_to_snake("HostName"), "host_name")

    def test_acronym_prefix(self):
        self.assertEqual(adcap._pascal_to_snake("PDCEmulator"), "pdc_emulator")

    def test_acronym_in_middle(self):
        self.assertEqual(
            adcap._pascal_to_snake("DomainSID"), "domain_sid",
        )


if __name__ == "__main__":
    unittest.main()
