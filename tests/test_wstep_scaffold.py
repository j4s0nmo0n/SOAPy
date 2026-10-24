"""Smoke import of WS-Trust enrollment symbols now implemented.

Phase B/C/D coverage lives in the dedicated test files
(``test_crypto_csr.py``, ``test_xcep.py``, ``test_wstep.py``). This file
is kept as a sentinel so a future regression that breaks the module
layout surfaces immediately.
"""


def test_ws_trust_symbols_importable():
    from src.cert_enroll_wstep import (
        build_rst_request,
        parse_rstr_response,
        request_cert,
        run_enroll,
    )
    from src.cert_enroll_xcep import (
        get_policies,
        parse_get_policies_response,
        run_list_policies,
    )
    from src.crypto.csr import build_csr

    assert all(
        callable(fn)
        for fn in (
            build_csr,
            get_policies,
            parse_get_policies_response,
            run_list_policies,
            build_rst_request,
            request_cert,
            parse_rstr_response,
            run_enroll,
        )
    )
