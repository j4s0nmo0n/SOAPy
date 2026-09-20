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

    def _scalar(tag: str) -> str | None:
        """Extract the text of the first matching tag; None if nil or absent."""
        # Check for nil first
        nil_m = re.search(rf"<[^>]*{re.escape(tag)}[^>]+nil\s*=\s*\"true\"", resp)
        if nil_m:
            return None
        m = re.search(rf"<[^>]*{re.escape(tag)}[^>]*>([^<]*)<", resp)
        return m.group(1).strip() if m else None

    def _array(container_tag: str) -> list[str] | None:
        """Extract a list[str] from a container tag holding <ser:string> children.

        Returns None if the container has i:nil="true", [] if empty.
        """
        nil_m = re.search(
            rf"<[^>]*{re.escape(container_tag)}[^>]+nil\s*=\s*\"true\"", resp
        )
        if nil_m:
            return None
        block_m = re.search(
            rf"<[^>]*{re.escape(container_tag)}[^>]*>(.*?)</[^>]*{re.escape(container_tag)}>",
            resp,
            re.DOTALL,
        )
        if not block_m:
            return None
        return re.findall(r"<[^>]*string[^>]*>([^<]*)<", block_m.group(1))

    forest_mode_raw = _scalar("ForestMode")

    return {
        "application_partitions": _array("ApplicationPartitions") or [],
        "cross_forest_references": _array("CrossForestReferences"),
        "domain_naming_master": _scalar("DomainNamingMaster") or "",
        "domains": _array("Domains") or [],
        "forest_mode": int(forest_mode_raw) if forest_mode_raw and forest_mode_raw.isdigit() else 0,
        "global_catalogs": _array("GlobalCatalogs") or [],
        "name": _scalar("Name") or "",
        "root_domain": _scalar("RootDomain") or "",
        "schema_master": _scalar("SchemaMaster") or "",
        "sites": _array("Sites") or [],
        "spn_suffixes": _array("SPNSuffixes"),
        "upn_suffixes": _array("UPNSuffixes"),
    }
