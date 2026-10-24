"""In-process Kerberos TGT helper for the WS-Trust primitives.

``requests-gssapi`` reads tickets from a disk ccache pointed to by
``KRB5CCNAME`` and cannot consume a TGT held in memory. When SOAPy is
invoked with credentials in the connection string (``domain/user:pass@dc``)
or with ``-nt``, this helper performs an AS-REQ via impacket, writes the
resulting TGT to a ccache inside a temporary directory, and points
``KRB5CCNAME`` at it for the duration of the ``with`` block. On exit the
temp directory is removed and the previous ``KRB5CCNAME`` value (if any)
is restored, so the host user's system ccache is never touched.
"""

from __future__ import annotations

import contextlib
import logging
import os
import tempfile
from pathlib import Path
from typing import Iterator, Optional

from impacket.krb5 import constants
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5.types import Principal


log = logging.getLogger(__name__)


@contextlib.contextmanager
def inline_tgt_ccache(
    username: str,
    domain: str,
    password: Optional[str] = None,
    nt_hash: Optional[str] = None,
    lm_hash: Optional[str] = None,
    aes_key: Optional[str] = None,
    kdc_ip: Optional[str] = None,
) -> Iterator[str]:
    """Obtain a TGT via AS-REQ for ``username@domain`` and expose it via KRB5CCNAME.

    Writes the TGT to a ccache file under an auto-cleaned ``TemporaryDirectory``,
    sets ``KRB5CCNAME`` to that path, and restores the previous environment
    value on exit. Yields the ccache absolute path.
    """
    if not password and not nt_hash and not aes_key:
        raise ValueError("inline_tgt_ccache requires password, hash or aes_key")

    user_principal = Principal(
        username, type=constants.PrincipalNameType.NT_PRINCIPAL.value
    )

    log.info("Requesting TGT for %s@%s via impacket AS-REQ", username, domain)
    tgt, _cipher, old_session_key, session_key = getKerberosTGT(
        user_principal,
        password or "",
        domain,
        lm_hash or "",
        nt_hash or "",
        aes_key or "",
        kdcHost=kdc_ip,
    )

    with tempfile.TemporaryDirectory(prefix="soapy-krb-") as workdir:
        ccache_path = Path(workdir) / "krb5cc"
        ccache = CCache()
        ccache.fromTGT(tgt, old_session_key, session_key)
        ccache.saveFile(str(ccache_path))
        os.chmod(ccache_path, 0o600)

        previous = os.environ.get("KRB5CCNAME")
        os.environ["KRB5CCNAME"] = f"FILE:{ccache_path}"
        log.debug("KRB5CCNAME set to %s for this request", ccache_path)
        try:
            yield str(ccache_path)
        finally:
            if previous is None:
                os.environ.pop("KRB5CCNAME", None)
            else:
                os.environ["KRB5CCNAME"] = previous
