"""MS-XCEP ``GetPolicies`` client for AD CS enrollment-policy discovery.

See design doc §3.1 (MS-XCEP: SOAP 1.2 + WS-Addressing + Kerberos over
HTTPS, action
``http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies``),
§4.3 (API shape) and §5 (CLI surface: ``--list-policies-ws``, ``--cep-url``).

Response parsing fills a :class:`GetPoliciesResult` dataclass. Resolution of
``policyOIDReference`` into the actual template OID goes through the
``oIDs`` reference table included in the response. CA bundles (chain +
URIs) are captured too so Phase D can reuse them for the PFX output.
"""

from __future__ import annotations

import logging
import uuid
import xml.etree.ElementTree as ET
from base64 import b64decode
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import requests
import urllib3

try:
    from requests_gssapi import OPTIONAL as _GSS_OPTIONAL
    from requests_gssapi import HTTPSPNEGOAuth

    _HAS_GSSAPI = True
except ImportError:  # pragma: no cover - exercised in environments without the lib
    _HAS_GSSAPI = False

try:
    from requests_kerberos import OPTIONAL as _KRB_OPTIONAL
    from requests_kerberos import HTTPKerberosAuth

    _HAS_KERBEROS = True
except ImportError:  # pragma: no cover
    _HAS_KERBEROS = False

from cryptography import x509


SOAP_ENV_NS = "http://www.w3.org/2003/05/soap-envelope"
WSA_NS = "http://www.w3.org/2005/08/addressing"
XCEP_NS = "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy"
XCEP_ACTION = (
    "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/"
    "IPolicy/GetPolicies"
)

DEFAULT_CEP_PATH = "/ADPolicyProvider_CEP_Kerberos/service.svc/CEP"

DEFAULT_USER_AGENT = (
    "Mozilla/4.0 (compatible; MSIE 6.0; "
    "MS Web Services Client Protocol 4.0.30319.42000)"
)

_TEMPLATE_PATH = Path(__file__).parent / "templates" / "xcep_get_policies.xml"


@dataclass
class Template:
    name: str
    oid: str
    template_oid_ref: int
    cas: List[int] = field(default_factory=list)
    min_key_length: Optional[int] = None
    hash_algos: List[str] = field(default_factory=list)
    revision: Optional[str] = None


@dataclass
class CA:
    reference_id: int
    name: Optional[str] = None
    uris: List[str] = field(default_factory=list)
    cert_der: Optional[bytes] = None


@dataclass
class GetPoliciesResult:
    policy_id: str = ""
    templates: Dict[str, Template] = field(default_factory=dict)
    cas: Dict[int, CA] = field(default_factory=dict)
    oids: Dict[str, str] = field(default_factory=dict)
    _ref_to_oid: Dict[int, str] = field(default_factory=dict, repr=False)


def default_cep_url(remote_name: str) -> str:
    """Build the default MS-XCEP endpoint URL from the DC hostname."""
    return f"https://{remote_name}{DEFAULT_CEP_PATH}"


def kerberos_auth():
    """Return a requests auth handler that negotiates Kerberos from the ccache.

    Sends a ``tls-server-end-point`` channel binding (RFC 5929) derived from
    the server's TLS cert. IIS enables Extended Protection for Authentication
    by default on modern Windows Server — without CBT the server rejects the
    SPNEGO token with HTTP 401 even when the AP-REQ is otherwise valid.

    Prefers :mod:`requests_gssapi`; falls back to :mod:`requests_kerberos`.
    """
    if _HAS_GSSAPI:
        return HTTPSPNEGOAuth(
            mutual_authentication=_GSS_OPTIONAL,
            channel_bindings="tls-server-end-point",
        )
    if _HAS_KERBEROS:
        return HTTPKerberosAuth(
            mutual_authentication=_KRB_OPTIONAL,
            send_cbt=True,
        )
    raise RuntimeError(
        "Kerberos auth requires 'requests-gssapi' (preferred) or "
        "'requests-kerberos'. Install one, e.g.: pip install requests-gssapi"
    )


def build_get_policies_request(url: str, msg_id: Optional[str] = None) -> str:
    """Render the SOAP envelope for a GetPolicies request against ``url``."""
    if msg_id is None:
        msg_id = str(uuid.uuid4())
    return _TEMPLATE_PATH.read_text(encoding="utf-8").format(
        msg_id=msg_id, to_url=url
    )


def get_policies(
    host: str,
    auth,
    verify: bool = True,
    timeout: float = 30.0,
    user_agent: str = DEFAULT_USER_AGENT,
) -> GetPoliciesResult:
    """Call MS-XCEP ``GetPolicies`` against ``host`` (full CEP URL).

    Returns a parsed :class:`GetPoliciesResult`. Raises :class:`ConnectionError`
    with a lab-friendly message on TLS verification failure.
    """
    if not verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    body = build_get_policies_request(host)
    headers = {
        "Content-Type": f'application/soap+xml; charset=utf-8; action="{XCEP_ACTION}"',
        "User-Agent": user_agent,
    }
    try:
        resp = requests.post(
            host,
            data=body.encode("utf-8"),
            headers=headers,
            auth=auth,
            verify=verify,
            timeout=timeout,
        )
    except requests.exceptions.SSLError as exc:
        raise ConnectionError(
            "SSL verification failed. Use --insecure-ssl for lab testing, "
            "or add the Enterprise CA root to the system trust store."
        ) from exc
    resp.raise_for_status()
    return parse_get_policies_response(resp.content)


def parse_get_policies_response(xml_bytes: bytes) -> GetPoliciesResult:
    """Parse a GetPoliciesResponse body (SOAP envelope or bare XCEP response)."""
    root = ET.fromstring(xml_bytes)
    resp_elem = (
        root
        if root.tag == f"{{{XCEP_NS}}}GetPoliciesResponse"
        else root.find(f".//{{{XCEP_NS}}}GetPoliciesResponse")
    )
    if resp_elem is None:
        raise ValueError("Response has no <GetPoliciesResponse> element")

    response = resp_elem.find(f"{{{XCEP_NS}}}response")
    if response is None:
        raise ValueError("<GetPoliciesResponse> has no <response>")

    result = GetPoliciesResult(
        policy_id=_findtext(response, "policyID") or "",
    )

    oids_elem = resp_elem.find(f"{{{XCEP_NS}}}oIDs")
    if oids_elem is not None:
        for oid_elem in oids_elem.findall(f"{{{XCEP_NS}}}oID"):
            _parse_oid(oid_elem, result)

    cas_elem = resp_elem.find(f"{{{XCEP_NS}}}cAs")
    if cas_elem is not None:
        for ca_elem in cas_elem.findall(f"{{{XCEP_NS}}}cA"):
            _parse_ca(ca_elem, result)

    policies_elem = response.find(f"{{{XCEP_NS}}}policies")
    if policies_elem is not None:
        for policy_elem in policies_elem.findall(f"{{{XCEP_NS}}}policy"):
            try:
                tmpl = _parse_policy(policy_elem, result._ref_to_oid)
            except ValueError as exc:
                logging.warning("Skipping malformed policy: %s", exc)
                continue
            result.templates[tmpl.name] = tmpl

    return result


def _findtext(elem: ET.Element, local_name: str) -> Optional[str]:
    child = elem.find(f"{{{XCEP_NS}}}{local_name}")
    return child.text if child is not None else None


def _parse_oid(oid_elem: ET.Element, result: GetPoliciesResult) -> None:
    ref_text = _findtext(oid_elem, "oIDReferenceID")
    value = _findtext(oid_elem, "value")
    default_name = _findtext(oid_elem, "defaultName") or value or ""
    if ref_text is None or value is None:
        return
    try:
        ref_id = int(ref_text)
    except ValueError:
        return
    result._ref_to_oid[ref_id] = value
    result.oids[value] = default_name


def _parse_ca(ca_elem: ET.Element, result: GetPoliciesResult) -> None:
    ref_text = _findtext(ca_elem, "cAReferenceID")
    if ref_text is None:
        return
    try:
        ref_id = int(ref_text)
    except ValueError:
        return

    ca = CA(reference_id=ref_id)

    cert_text = _findtext(ca_elem, "certificate")
    if cert_text and cert_text.strip():
        try:
            ca.cert_der = b64decode(cert_text)
            cert = x509.load_der_x509_certificate(ca.cert_der)
            ca.name = cert.subject.rfc4514_string()
        except Exception as exc:  # noqa: BLE001 - best-effort parse
            logging.warning("Failed to parse CA cert for ref %s: %s", ref_id, exc)

    uris_elem = ca_elem.find(f"{{{XCEP_NS}}}uris")
    if uris_elem is not None:
        for uri_elem in uris_elem.findall(f"{{{XCEP_NS}}}cAURI"):
            u = _findtext(uri_elem, "uri")
            if u:
                ca.uris.append(u)

    result.cas[ref_id] = ca


def _parse_policy(policy_elem: ET.Element, ref_to_oid: Dict[int, str]) -> Template:
    oid_ref_text = _findtext(policy_elem, "policyOIDReference")
    if oid_ref_text is None:
        raise ValueError("policy missing policyOIDReference")
    try:
        oid_ref = int(oid_ref_text)
    except ValueError as exc:
        raise ValueError(f"policyOIDReference not an int: {oid_ref_text!r}") from exc
    oid = ref_to_oid.get(oid_ref)
    if oid is None:
        raise ValueError(f"unknown policyOIDReference {oid_ref}")

    attrs = policy_elem.find(f"{{{XCEP_NS}}}attributes")
    if attrs is None:
        raise ValueError("policy missing <attributes>")
    name = _findtext(attrs, "commonName")
    if not name:
        raise ValueError("policy missing <commonName>")

    cas: List[int] = []
    cas_elem = policy_elem.find(f"{{{XCEP_NS}}}cAs")
    if cas_elem is not None:
        for ref_elem in cas_elem.findall(f"{{{XCEP_NS}}}cAReference"):
            if ref_elem.text:
                try:
                    cas.append(int(ref_elem.text))
                except ValueError:
                    pass

    min_key_length: Optional[int] = None
    pka = attrs.find(f"{{{XCEP_NS}}}privateKeyAttributes")
    if pka is not None:
        mkl_text = _findtext(pka, "minimalKeyLength")
        if mkl_text:
            try:
                min_key_length = int(mkl_text)
            except ValueError:
                pass

    hash_algos: List[str] = []
    ha_ref = _findtext(attrs, "hashAlgorithmOIDReference")
    if ha_ref:
        try:
            algo_oid = ref_to_oid.get(int(ha_ref))
        except ValueError:
            algo_oid = None
        if algo_oid:
            hash_algos.append(algo_oid)

    revision: Optional[str] = None
    rev_elem = attrs.find(f"{{{XCEP_NS}}}revision")
    if rev_elem is not None:
        major = _findtext(rev_elem, "majorRevision") or "0"
        minor = _findtext(rev_elem, "minorRevision") or "0"
        revision = f"{major}.{minor}"

    return Template(
        name=name,
        oid=oid,
        template_oid_ref=oid_ref,
        cas=cas,
        min_key_length=min_key_length,
        hash_algos=hash_algos,
        revision=revision,
    )


def format_policies_table(result: GetPoliciesResult) -> str:
    """Render the result as a human-readable table (used by ``--list-policies-ws``)."""
    header = ("Template", "OID", "Min Key", "CA refs")
    rows = [header]
    for name in sorted(result.templates):
        tmpl = result.templates[name]
        rows.append(
            (
                tmpl.name,
                tmpl.oid,
                str(tmpl.min_key_length) if tmpl.min_key_length is not None else "-",
                ",".join(str(c) for c in tmpl.cas) if tmpl.cas else "-",
            )
        )
    widths = [max(len(r[i]) for r in rows) for i in range(len(header))]
    sep = "  "
    lines = [sep.join(cell.ljust(w) for cell, w in zip(row, widths)) for row in rows]
    lines.append("")
    lines.append(f"Policy ID: {result.policy_id or '(none)'}")
    if result.cas:
        lines.append("CAs:")
        for ref, ca in sorted(result.cas.items()):
            name_part = ca.name or "(no cert)"
            uris_part = ", ".join(ca.uris) if ca.uris else "(no URIs)"
            lines.append(f"  [{ref}] {name_part}")
            lines.append(f"       {uris_part}")
    return "\n".join(lines)


def run_list_policies(
    remote_name: str,
    cep_url: Optional[str],
    ca_name: Optional[str],
    insecure_ssl: bool,
    user_agent: str = DEFAULT_USER_AGENT,
) -> None:
    """CLI dispatch for ``--list-policies-ws`` — prints a table or exits non-zero."""
    if insecure_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    url = cep_url
    if not url:
        if not ca_name:
            logging.critical(
                "--list-policies-ws requires either --cep-url or --ca (to derive the URL)"
            )
            raise SystemExit(1)
        url = default_cep_url(remote_name)

    try:
        auth = kerberos_auth()
    except RuntimeError as exc:
        logging.critical(str(exc))
        raise SystemExit(1) from exc

    try:
        result = get_policies(url, auth, verify=not insecure_ssl, user_agent=user_agent)
    except ConnectionError as exc:
        logging.critical(str(exc))
        raise SystemExit(1) from exc
    except requests.HTTPError as exc:
        logging.critical("MS-XCEP GetPolicies failed: %s", exc)
        raise SystemExit(1) from exc

    print(format_policies_table(result))
