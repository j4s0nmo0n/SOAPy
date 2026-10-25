"""MS-ADCAP primitives for SOAPy.

Implementation gotchas (all empirically verified against a real DC):

1. <ca:Server>ldap:389</ca:Server> is MANDATORY in the SOAP header.
   Omitting it causes the server to return a DeserializationFailed fault
   before it even inspects the body.

2. Body elements MUST be in strict alphabetical order (WCF DataContract
   serialisation rule, undocumented in the public WSDL). An out-of-order
   element is silently dropped and the server treats that parameter as
   null — no error, no warning, just a missing value.

3. Enum values MUST be sent as strings, NOT integers. Although the WSDL
   uses <EnumerationValue>2</EnumerationValue> for e.g. CanonicalName,
   the actual SOAP wire format expects the string form:
   <ca:FormatDesired>CanonicalName</ca:FormatDesired>.
   Sending an integer produces a DeserializationFailed fault.
"""

import logging
import re
from uuid import uuid4

from .adws import ADWSConnect

NS_CA = "http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions"
NS_SER = "http://schemas.microsoft.com/2003/10/Serialization/Arrays"
NS_XSI = "http://www.w3.org/2001/XMLSchema-instance"


class ADCAPFault(Exception):
    """Raised when the server returns a <s:Fault> in a ADCAP response.

    Attributes:
        message: Short human-readable description extracted from the fault.
        error_code: Numeric code from the CustomActionFault body, or None.
        extended: Raw extended error text, or None.
    """

    def __init__(self, message: str, error_code: int | None, extended: str | None) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.extended = extended


def _send_recv(client: ADWSConnect, soap: str) -> str:
    """Send a SOAP message and return the response as a string."""
    client._nmf.send(soap)
    resp = client._nmf.recv()
    return resp if isinstance(resp, str) else str(resp)


# Local-name opener: ``<`` then an optional ``prefix:`` (strict word chars
# + ``.`` / ``-`` so a greedy ``[^>]*`` doesn't eat a longer suffix tag --
# e.g. without this anchor, _scalar("Name") would match
# ``<ns0:DistinguishedName>`` and capture the DN).
_NS_PREFIX = r"(?:[A-Za-z_][\w.-]*:)?"


def _scalar(resp: str, tag: str) -> str | None:
    """Extract the text of the first ``<tag>`` element.

    Returns None if the element carries ``i:nil="true"`` or is absent.
    Namespace prefixes are ignored (SOAPy pattern); matching is on local
    name. A ``\\b`` boundary after the tag name prevents the lookup for
    ``Name`` from greedily matching ``DistinguishedName`` and similar.
    """
    nil_m = re.search(
        rf"<{_NS_PREFIX}{re.escape(tag)}\b[^>]*nil\s*=\s*\"true\"", resp
    )
    if nil_m:
        return None
    m = re.search(
        rf"<{_NS_PREFIX}{re.escape(tag)}\b[^>]*>([^<]*)<", resp
    )
    return m.group(1).strip() if m else None


def _array(resp: str, tag: str) -> list[str] | None:
    """Extract a list[str] from ``<tag>`` wrapping ``<string>`` children.

    Returns None if the wrapper has ``i:nil="true"``, [] if the wrapper
    exists but has no ``<string>`` children, and the list of values
    otherwise. Any namespace prefix on ``<string>`` (``a:``, ``b:``,
    ``ser:``, ``ns1:``, …) is accepted.
    """
    nil_m = re.search(
        rf"<{_NS_PREFIX}{re.escape(tag)}\b[^>]*nil\s*=\s*\"true\"", resp
    )
    if nil_m:
        return None
    block_m = re.search(
        rf"<{_NS_PREFIX}{re.escape(tag)}\b[^>]*>(.*?)</{_NS_PREFIX}{re.escape(tag)}>",
        resp,
        re.DOTALL,
    )
    if not block_m:
        return None
    return re.findall(
        rf"<{_NS_PREFIX}string\b[^>]*>([^<]*)<", block_m.group(1)
    )


def _check_fault(xml_str: str) -> None:
    """Raise ADCAPFault if the response contains a SOAP Fault element.

    Extracts fields from <CustomActionFault> which may contain
    <ArgumentError>, <DirectoryError>, or <Error> sub-elements.
    Uses regex to avoid namespace prefix ambiguity.
    """
    if "<Fault" not in xml_str and ":Fault" not in xml_str:
        return

    def _re_text(tag: str, s: str) -> str | None:
        m = re.search(rf"<[^>]*:?{re.escape(tag)}[^>]*>([^<]*)<", s)
        return m.group(1).strip() if m else None

    # Try to get a short message from faultstring or Text
    short = _re_text("faultstring", xml_str) or _re_text("Text", xml_str) or "ADCAP fault"

    # error_code from <ErrorCode> or <Code>
    code_str = _re_text("ErrorCode", xml_str) or _re_text("Code", xml_str)
    error_code: int | None = None
    if code_str and code_str.isdigit():
        error_code = int(code_str)

    # Extended text from <Message> or <ExtendedErrorInfo>
    extended = _re_text("ExtendedErrorInfo", xml_str) or _re_text("Message", xml_str)

    logging.error("ADCAP fault: %s (code=%s, extended=%s)", short, error_code, extended)
    raise ADCAPFault(short, error_code, extended)


def translate_name(
    client: ADWSConnect,
    names: list[str],
    format_offered: str = "DistinguishedName",
    format_desired: str = "CanonicalName",
) -> list[tuple[str | None, int]]:
    """MS-ADCAP AccountManagement TranslateName.

    Translates each DN into the desired name format. Behavior notes
    observed empirically:
      - When all names in the batch parse as valid DNs per RFC 4514,
        the server acts as a pure syntactic transformer: it returns
        Result=0 with a fabricated CanonicalName even for objects
        that do NOT exist in the directory, and even for DNs
        pointing to unknown domains.
      - When at least one name in the batch is not RFC 4514 parseable
        (missing '=', empty component, trailing comma), the server
        switches to directory-verification mode for the whole batch:
        nonexistent objects then return Result=2 with a nil Name.
      - The FormatOffered/FormatDesired parameters MUST be sent as
        strings ("DistinguishedName", "CanonicalName"). Do NOT use
        the integer EnumerationValue from the WSDL.

    Args:
        client: an ADWSConnect instance built via
            ADWSConnect.accounts_cap_client(...).
        names: list of names to translate.
        format_offered: input format (default "DistinguishedName").
        format_desired: output format (default "CanonicalName").

    Returns:
        A list of (translated_name, result_code) tuples, one per
        input name. translated_name is None when the server returned
        i:nil="true"; result_code is the per-name Result (0 = ok,
        other = error, e.g. 2 = malformed/unresolved).
    """
    uid = str(uuid4())
    fqdn = client._fqdn

    names_xml = "".join(
        f"<ser:string>{n}</ser:string>" for n in names
    )

    # Body elements in alphabetical order: FormatDesired < FormatOffered < Names
    soap = f"""<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://www.w3.org/2005/08/addressing"
    xmlns:ca="http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions"
    xmlns:ser="http://schemas.microsoft.com/2003/10/Serialization/Arrays">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions/AccountManagement/TranslateName</a:Action>
        <ca:Server>ldap:389</ca:Server>
        <a:MessageID>urn:uuid:{uid}</a:MessageID>
        <a:ReplyTo>
            <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
        </a:ReplyTo>
        <a:To s:mustUnderstand="1">net.tcp://{fqdn}:9389/ActiveDirectoryWebServices/Windows/AccountManagement</a:To>
    </s:Header>
    <s:Body>
        <ca:TranslateNameRequest>
            <ca:FormatDesired>{format_desired}</ca:FormatDesired>
            <ca:FormatOffered>{format_offered}</ca:FormatOffered>
            <ca:Names>
                {names_xml}
            </ca:Names>
        </ca:TranslateNameRequest>
    </s:Body>
</s:Envelope>"""

    logging.info("ADCAP TranslateName: %d name(s) via %s", len(names), fqdn)
    resp = _send_recv(client, soap)
    _check_fault(resp)

    # Parse results with regex — tags are predictable and this avoids
    # namespace-prefix headaches with ElementTree on raw NMF responses.
    # Each result block looks like:
    #   <ca:ActiveDirectoryNameTranslateResult>
    #     <ca:Name i:nil="true"/> or <ca:Name>value</ca:Name>
    #     <ca:Result>0</ca:Result>
    #   </ca:ActiveDirectoryNameTranslateResult>
    results: list[tuple[str | None, int]] = []

    for block in re.findall(
        r"<[^>]*ActiveDirectoryNameTranslateResult[^>]*>(.*?)</[^>]*ActiveDirectoryNameTranslateResult>",
        resp,
        re.DOTALL,
    ):
        # Name element — check for i:nil="true" first
        name_nil = re.search(r'<[^>]*Name[^>]+nil\s*=\s*"true"', block)
        if name_nil:
            translated: str | None = None
        else:
            name_m = re.search(r"<[^>]*Name[^>]*>([^<]*)<", block)
            translated = name_m.group(1).strip() if name_m else None

        result_m = re.search(r"<[^>]*Result[^>]*>(\d+)<", block)
        result_code = int(result_m.group(1)) if result_m else -1

        results.append((translated, result_code))

    logging.info("TranslateName returned %d result(s)", len(results))
    return results


def get_ad_forest(client: ADWSConnect) -> dict:
    """MS-ADCAP TopologyManagement GetADForest.

    Returns the forest topology as seen by the contacted DC. Behavior
    note observed empirically: the request's optional Identity
    parameter is silently ignored by the server; it always returns
    the forest hosted by the DC contacted, regardless of what
    forest name (if any) was passed. To reach another forest,
    contact a DC of that forest directly.

    Args:
        client: an ADWSConnect instance built via
            ADWSConnect.topology_cap_client(...).

    Returns:
        A dict with keys: application_partitions (list[str]),
        cross_forest_references (list[str] | None),
        domain_naming_master (str), domains (list[str]),
        forest_mode (int), global_catalogs (list[str]), name (str),
        root_domain (str), spn_suffixes (list[str] | None),
        schema_master (str), sites (list[str]),
        upn_suffixes (list[str] | None).
    """
    uid = str(uuid4())
    fqdn = client._fqdn

    soap = f"""<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://www.w3.org/2005/08/addressing"
    xmlns:ca="http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions/TopologyManagement/GetADForest</a:Action>
        <ca:Server>ldap:389</ca:Server>
        <a:MessageID>urn:uuid:{uid}</a:MessageID>
        <a:ReplyTo>
            <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
        </a:ReplyTo>
        <a:To s:mustUnderstand="1">net.tcp://{fqdn}:9389/ActiveDirectoryWebServices/Windows/TopologyManagement</a:To>
    </s:Header>
    <s:Body>
        <ca:GetADForestRequest></ca:GetADForestRequest>
    </s:Body>
</s:Envelope>"""

    logging.info("ADCAP GetADForest via %s", fqdn)
    resp = _send_recv(client, soap)
    _check_fault(resp)

    forest_mode_raw = _scalar(resp, "ForestMode")

    return {
        "application_partitions": _array(resp, "ApplicationPartitions") or [],
        "cross_forest_references": _array(resp, "CrossForestReferences"),
        "domain_naming_master": _scalar(resp, "DomainNamingMaster") or "",
        "domains": _array(resp, "Domains") or [],
        "forest_mode": int(forest_mode_raw) if forest_mode_raw and forest_mode_raw.isdigit() else 0,
        "global_catalogs": _array(resp, "GlobalCatalogs") or [],
        "name": _scalar(resp, "Name") or "",
        "root_domain": _scalar(resp, "RootDomain") or "",
        "schema_master": _scalar(resp, "SchemaMaster") or "",
        "sites": _array(resp, "Sites") or [],
        "spn_suffixes": _array(resp, "SPNSuffixes"),
        "upn_suffixes": _array(resp, "UPNSuffixes"),
    }


# ---------------------------------------------------------------------------
# Shared SOAP envelope for TopologyManagement primitives
# ---------------------------------------------------------------------------


def _topology_envelope(fqdn: str, uid: str, action: str, body: str) -> str:
    """Build a WS-Addressing SOAP envelope targeting the TopologyManagement
    endpoint. ``body`` is the raw <s:Body> content (one Request element).
    ``<ca:Server>ldap:389</ca:Server>`` is mandatory server-side (see
    module docstring, gotcha #1).
    """
    return f"""<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://www.w3.org/2005/08/addressing"
    xmlns:ca="http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions/TopologyManagement/{action}</a:Action>
        <ca:Server>ldap:389</ca:Server>
        <a:MessageID>urn:uuid:{uid}</a:MessageID>
        <a:ReplyTo>
            <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
        </a:ReplyTo>
        <a:To s:mustUnderstand="1">net.tcp://{fqdn}:9389/ActiveDirectoryWebServices/Windows/TopologyManagement</a:To>
    </s:Header>
    <s:Body>
        {body}
    </s:Body>
</s:Envelope>"""


def get_version(client: ADWSConnect) -> dict:
    """MS-ADCAP TopologyManagement GetVersion.

    Returns the ADWS service version advertised by the DC. Useful for
    fingerprinting the Windows Server build (2008 R2 vs 2012 R2 vs 2016
    vs 2019 vs 2022 vs 2025) and for a cheap end-to-end health check of
    the TopologyManagement endpoint.

    Returns:
        A dict with keys ``version_major`` (int), ``version_minor``
        (int) and ``version_string`` (str).
    """
    uid = str(uuid4())
    body = "<ca:GetVersionRequest/>"
    soap = _topology_envelope(client._fqdn, uid, "GetVersion", body)
    logging.info("ADCAP GetVersion via %s", client._fqdn)
    resp = _send_recv(client, soap)
    _check_fault(resp)
    major = _scalar(resp, "VersionMajor") or ""
    minor = _scalar(resp, "VersionMinor") or ""
    return {
        "version_major": int(major) if major.isdigit() else 0,
        "version_minor": int(minor) if minor.isdigit() else 0,
        "version_string": _scalar(resp, "VersionString") or "",
    }


def get_ad_domain(client: ADWSConnect, identity: str | None = None) -> dict:
    """MS-ADCAP TopologyManagement GetADDomain.

    Returns the domain object hosted by the contacted DC, or the domain
    identified by ``identity`` when supplied. Response structure mirrors
    GetADForest: a <Domain> wrapper under <GetADDomainResponse> with a
    mix of scalars, string-array wrappers and ``xsi:nil`` placeholders.

    Args:
        client: an ADWSConnect built via
            ``ADWSConnect.topology_cap_client(...)``.
        identity: optional domain identity (DN, NetBIOS name, DNS name).

    Returns:
        A dict with the parsed Domain fields. Array fields default to
        ``[]`` when empty, nullable scalars to ``None``.
    """
    uid = str(uuid4())
    identity_block = f"<ca:Identity>{identity}</ca:Identity>" if identity else ""
    body = f"<ca:GetADDomainRequest>{identity_block}</ca:GetADDomainRequest>"
    soap = _topology_envelope(client._fqdn, uid, "GetADDomain", body)
    logging.info("ADCAP GetADDomain via %s", client._fqdn)
    resp = _send_recv(client, soap)
    _check_fault(resp)

    domain_mode_raw = _scalar(resp, "DomainMode") or ""
    return {
        "allowed_dns_suffixes": _array(resp, "AllowedDNSSuffixes"),
        "applied_group_policies": _array(resp, "AppliedGroupPolicies") or [],
        "child_domains": _array(resp, "ChildDomains") or [],
        "computers_container": _scalar(resp, "ComputersContainer") or "",
        "deleted_objects_container": _scalar(resp, "DeletedObjectsContainer") or "",
        "distinguished_name": _scalar(resp, "DistinguishedName") or "",
        "dns_root": _scalar(resp, "DNSRoot") or "",
        "domain_controllers_container": _scalar(resp, "DomainControllersContainer") or "",
        "domain_mode": int(domain_mode_raw) if domain_mode_raw.isdigit() else 0,
        "domain_sid": _decode_binary_sid_b64(_scalar(resp, "DomainSID") or ""),
        "foreign_security_principals_container": _scalar(resp, "ForeignSecurityPrincipalsContainer") or "",
        "forest": _scalar(resp, "Forest") or "",
        "infrastructure_master": _scalar(resp, "InfrastructureMaster") or "",
        "last_logon_replication_interval": _scalar(resp, "LastLogonReplicationInterval"),
        "lost_and_found_container": _scalar(resp, "LostAndFoundContainer") or "",
        "managed_by": _scalar(resp, "ManagedBy"),
        "name": _scalar(resp, "Name") or "",
        "net_bios_name": _scalar(resp, "NetBIOSName") or "",
        "object_class": _scalar(resp, "ObjectClass") or "",
        "object_guid": _scalar(resp, "ObjectGuid") or "",
        "object_types": _array(resp, "ObjectTypes") or [],
        "parent_domain": _scalar(resp, "ParentDomain"),
        "pdc_emulator": _scalar(resp, "PDCEmulator") or "",
        "quotas_container": _scalar(resp, "QuotasContainer") or "",
        "read_only_replica_directory_server": _array(resp, "ReadOnlyReplicaDirectoryServer"),
        "reference_server": _scalar(resp, "ReferenceServer") or "",
        "replica_directory_server": _array(resp, "ReplicaDirectoryServer") or [],
        "rid_master": _scalar(resp, "RIDMaster") or "",
        "subordinate_references": _array(resp, "SubordinateReferences") or [],
        "systems_container": _scalar(resp, "SystemsContainer") or "",
        "users_container": _scalar(resp, "UsersContainer") or "",
    }


def _parse_dc_payload(resp: str) -> dict:
    """Generic walker for the GetADDomainController response.

    Finds every child element inside the ``<DomainController>`` wrapper
    (or the response envelope if the wrapper is absent) and classifies
    each one:

      - a child with ``i:nil="true"`` → ``None``
      - a child containing ``<string>`` grandchildren → list[str]
      - a child containing other repeated element children (e.g.
        ``<ActiveDirectoryOperationMasterRole>`` under
        ``<OperationMasterRole>``) → list[str] of their text() values
      - a child with plain text → scalar string

    Keys are snake_case versions of the server's PascalCase tags. The
    parser is deliberately generic so the rendering layer can treat
    arbitrary DC fields uniformly.
    """
    wrapper_m = re.search(
        r"<[^>]*:?DomainController[^>]*>(.*?)</[^>]*:?DomainController>",
        resp,
        re.DOTALL,
    )
    body = wrapper_m.group(1) if wrapper_m else resp

    out: dict = {}
    for match in re.finditer(
        r"<([A-Za-z0-9]+:)?([A-Z][A-Za-z0-9]+)\b([^/>]*?)"
        r"(?:/>|>(.*?)</(?:[A-Za-z0-9]+:)?\2>)",
        body,
        re.DOTALL,
    ):
        tag = match.group(2)
        attrs = match.group(3) or ""
        inner = match.group(4)
        key = _pascal_to_snake(tag)

        if "nil" in attrs and re.search(r'nil\s*=\s*"true"', attrs):
            out[key] = None
            continue

        if inner is None:
            out[key] = ""
            continue

        if re.search(rf"<{_NS_PREFIX}string\b", inner):
            out[key] = re.findall(
                rf"<{_NS_PREFIX}string\b[^>]*>([^<]*)<", inner
            )
            continue

        if "<" in inner:
            # Nested element array: a wrapper whose children are repeated
            # typed elements (e.g. <ActiveDirectoryOperationMasterRole>…</…>
            # under <OperationMasterRole>). Flatten their text() values.
            out[key] = re.findall(r">([^<>]+)</", inner)
            continue

        out[key] = inner.strip()

    return out


def _decode_binary_sid_b64(b64: str) -> str:
    """Decode a base64-encoded binary SID to its canonical ``S-1-5-…`` form.

    The server returns ``DomainSID`` as ``xs:base64Binary``. Returns the
    input unchanged if it does not decode as a well-formed LDAP SID,
    which keeps unit-test fixtures (``S-1-5-21-1-2-3``) and any future
    pre-decoded payloads passing through untouched.
    """
    if not b64:
        return b64
    try:
        from base64 import b64decode
        from impacket.ldap.ldaptypes import LDAP_SID
        return LDAP_SID(b64decode(b64)).formatCanonical()
    except Exception:
        return b64


def _pascal_to_snake(name: str) -> str:
    """``PDCEmulator`` -> ``pdc_emulator``; ``IPv4Address`` -> ``i_pv4_address``
    style conversion. Keeps consecutive uppercase as one word break group.
    """
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    s = re.sub(r"([a-z\d])([A-Z])", r"\1_\2", s)
    return s.lower()


def get_ad_domain_controller(
    client: ADWSConnect, ntds_settings_dn: list[str]
) -> dict:
    """MS-ADCAP TopologyManagement GetADDomainController.

    The server rejects empty requests with an ArgumentError on the
    ``NtdsSettingsDN`` parameter even though the WSDL marks it optional
    (observed empirically — undocumented gotcha). The caller MUST supply
    at least one NTDS Settings DN. These are typically discoverable by
    LDAP-searching ``CN=Sites,CN=Configuration,...`` for
    ``(objectClass=nTDSDSA)``, or by inspecting
    ``ReplicaDirectoryServer`` from a prior GetADForest / GetADDomain.

    Args:
        client: an ADWSConnect built via
            ``ADWSConnect.topology_cap_client(...)``.
        ntds_settings_dn: non-empty list of ``CN=NTDS Settings,...`` DNs.

    Returns:
        A dict with the parsed DomainController fields.
    """
    if not ntds_settings_dn:
        raise ValueError(
            "ntds_settings_dn must be a non-empty list of DN strings "
            "(the server rejects an empty NtdsSettingsDN with an "
            "ArgumentError even though the WSDL marks it optional)"
        )
    uid = str(uuid4())
    ntds_elems = "".join(
        f"<b:string>{dn}</b:string>" for dn in ntds_settings_dn
    )
    body = (
        f'<ca:GetADDomainControllerRequest>'
        f'<ca:NtdsSettingsDN xmlns:b="http://schemas.microsoft.com/2003/10/Serialization/Arrays">'
        f'{ntds_elems}'
        f'</ca:NtdsSettingsDN>'
        f'</ca:GetADDomainControllerRequest>'
    )
    soap = _topology_envelope(
        client._fqdn, uid, "GetADDomainController", body
    )
    logging.info(
        "ADCAP GetADDomainController via %s (%d DN(s))",
        client._fqdn,
        len(ntds_settings_dn),
    )
    resp = _send_recv(client, soap)
    _check_fault(resp)
    return _parse_dc_payload(resp)
