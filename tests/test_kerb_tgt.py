"""Tests for ``src.kerb_tgt`` and its wiring into the WS-Trust dispatch.

The AS-REQ itself is mocked — the goal is to pin down the contract:
``KRB5CCNAME`` is set to a FILE: path pointing inside an auto-cleaned
``TemporaryDirectory`` while the ``with`` block runs, and the previous
value (if any) is restored on exit. The dispatch in ``src.soa`` must use
the context when creds are available (connection-string password or
``-nt``) and ``nullcontext`` when they are not.
"""

from __future__ import annotations

import argparse
import contextlib
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from src import kerb_tgt
from src import soa as soa_mod


class _FakeKey:
    """Minimal stand-in for impacket's Key / session_key objects."""


def _fake_get_tgt(user_principal, password, domain, lm, nt, aes, kdcHost=None):
    return b"TGT_BLOB", object(), _FakeKey(), _FakeKey()


@contextlib.contextmanager
def _patched_ccache():
    with patch.object(kerb_tgt, "getKerberosTGT", side_effect=_fake_get_tgt), \
            patch.object(kerb_tgt, "CCache") as fake_ccache_cls:
        instance = fake_ccache_cls.return_value
        instance.fromTGT = lambda *a, **kw: None
        instance.saveFile = lambda p: Path(p).write_bytes(b"")
        yield fake_ccache_cls


# ---------------------------------------------------------------------------
# Context manager contract
# ---------------------------------------------------------------------------


def test_inline_tgt_ccache_sets_env_and_restores_it(monkeypatch):
    monkeypatch.delenv("KRB5CCNAME", raising=False)
    with _patched_ccache():
        with kerb_tgt.inline_tgt_ccache(
            username="yuji", domain="jjk.local", password="P@ssword!"
        ) as ccache_path:
            assert os.environ["KRB5CCNAME"] == f"FILE:{ccache_path}"
            assert Path(ccache_path).exists()
    assert "KRB5CCNAME" not in os.environ


def test_inline_tgt_ccache_restores_previous_env(monkeypatch):
    monkeypatch.setenv("KRB5CCNAME", "FILE:/tmp/original.ccache")
    with _patched_ccache():
        with kerb_tgt.inline_tgt_ccache(
            username="yuji", domain="jjk.local", password="P@ssword!"
        ):
            assert os.environ["KRB5CCNAME"].startswith("FILE:")
            assert os.environ["KRB5CCNAME"] != "FILE:/tmp/original.ccache"
    assert os.environ["KRB5CCNAME"] == "FILE:/tmp/original.ccache"


def test_inline_tgt_ccache_cleanup_tempdir(monkeypatch):
    monkeypatch.delenv("KRB5CCNAME", raising=False)
    saved = {}
    with _patched_ccache():
        with kerb_tgt.inline_tgt_ccache(
            username="yuji", domain="jjk.local", password="P@ssword!"
        ) as ccache_path:
            saved["p"] = ccache_path
            assert Path(ccache_path).exists()
            assert "soapy-krb-" in ccache_path
    assert not Path(saved["p"]).exists()
    assert not Path(saved["p"]).parent.exists()


def test_inline_tgt_ccache_requires_a_secret():
    with pytest.raises(ValueError):
        with kerb_tgt.inline_tgt_ccache(username="yuji", domain="jjk.local"):
            pass


def test_inline_tgt_ccache_passes_hash_and_kdc(monkeypatch):
    monkeypatch.delenv("KRB5CCNAME", raising=False)
    captured = {}

    def spy(user_principal, password, domain, lm, nt, aes, kdcHost=None):
        captured.update(dict(password=password, lm=lm, nt=nt, aes=aes, kdc=kdcHost))
        return b"TGT", object(), _FakeKey(), _FakeKey()

    with patch.object(kerb_tgt, "getKerberosTGT", side_effect=spy), \
            patch.object(kerb_tgt, "CCache") as fake_ccache_cls:
        fake_ccache_cls.return_value.fromTGT = lambda *a, **kw: None
        fake_ccache_cls.return_value.saveFile = lambda p: Path(p).write_bytes(b"")
        with kerb_tgt.inline_tgt_ccache(
            username="yuji",
            domain="jjk.local",
            nt_hash="31d6cfe0d16ae931b73c59d7e0c089c0",
            kdc_ip="dc-curse.jjk.local",
        ):
            pass

    assert captured["password"] == ""
    assert captured["nt"] == "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert captured["lm"] == ""
    assert captured["kdc"] == "dc-curse.jjk.local"


# ---------------------------------------------------------------------------
# Dispatch wiring in src.soa.run_cli
# ---------------------------------------------------------------------------


class _LenientNamespace(argparse.Namespace):
    """argparse.Namespace that returns None for unset attributes.

    The dispatch in ``run_cli`` touches many ``options.X`` flags across
    unrelated primitives; falling back to None keeps the tests focused on
    the WS-Trust path without enumerating every unrelated flag.
    """

    def __getattr__(self, name):
        return None


def _base_options(**overrides):
    """Namespace with just the WS-Trust fields plus a lenient default."""
    ns = _LenientNamespace()
    defaults = dict(
        connection="jjk.local/yuji:P@ssword!@dc-curse.jjk.local",
        debug=False,
        ts=False,
        nthash=None,
        kerberos=False,
        list_policies_ws=False,
        enroll_ws=False,
        cep_url=None,
        ces_url=None,
        wstep_ca=None,
        wstep_template=None,
        wstep_upn=None,
        wstep_out=None,
        insecure_ssl=False,
        user_agent=None,
        auth_dc=None,
    )
    defaults.update(overrides)
    for k, v in defaults.items():
        setattr(ns, k, v)
    return ns


def _invoke_run_cli(ns, monkeypatch):
    """Drive ``run_cli`` with a prebuilt Namespace, mocking argparse + parse_target."""
    import argparse as _argparse

    def fake_parse_args(self, *a, **kw):
        return ns

    monkeypatch.setattr(_argparse.ArgumentParser, "parse_args", fake_parse_args)

    # Reuse impacket's actual parse_target so the connection string is
    # tokenized exactly like production.
    from impacket.examples.utils import parse_target as _real_parse_target
    monkeypatch.setattr(soa_mod, "parse_target", _real_parse_target)
    soa_mod.run_cli()


def test_dispatch_uses_inline_tgt_when_password_in_connection_string(monkeypatch):
    ns = _base_options(enroll_ws=True)

    from src import cert_enroll_wstep as wstep_mod
    monkeypatch.setattr(wstep_mod, "run_enroll", lambda **_: None)

    calls = {"n": 0, "kw": None}

    @contextlib.contextmanager
    def fake_inline(**kw):
        calls["n"] += 1
        calls["kw"] = kw
        yield "/fake/ccache"

    from src import kerb_tgt as kerb_tgt_mod
    monkeypatch.setattr(kerb_tgt_mod, "inline_tgt_ccache", fake_inline)

    _invoke_run_cli(ns, monkeypatch)

    assert calls["n"] == 1
    assert calls["kw"]["username"] == "yuji"
    assert calls["kw"]["password"] == "P@ssword!"
    assert calls["kw"]["domain"] == "jjk.local"
    assert calls["kw"]["kdc_ip"] == "dc-curse.jjk.local"


def test_dispatch_parses_nthash_LMNT(monkeypatch):
    ns = _base_options(
        connection="jjk.local/yuji@dc-curse.jjk.local",  # no password
        enroll_ws=True,
        nthash="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
    )

    from src import cert_enroll_wstep as wstep_mod
    monkeypatch.setattr(wstep_mod, "run_enroll", lambda **_: None)

    seen = {}

    @contextlib.contextmanager
    def fake_inline(**kw):
        seen.update(kw)
        yield "/fake"

    from src import kerb_tgt as kerb_tgt_mod
    monkeypatch.setattr(kerb_tgt_mod, "inline_tgt_ccache", fake_inline)

    _invoke_run_cli(ns, monkeypatch)

    assert seen["lm_hash"] == "aad3b435b51404eeaad3b435b51404ee"
    assert seen["nt_hash"] == "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert seen["password"] is None


def test_dispatch_parses_nthash_NT_only(monkeypatch):
    ns = _base_options(
        connection="jjk.local/yuji@dc-curse.jjk.local",
        enroll_ws=True,
        nthash="31d6cfe0d16ae931b73c59d7e0c089c0",
    )

    from src import cert_enroll_wstep as wstep_mod
    monkeypatch.setattr(wstep_mod, "run_enroll", lambda **_: None)

    seen = {}

    @contextlib.contextmanager
    def fake_inline(**kw):
        seen.update(kw)
        yield "/fake"

    from src import kerb_tgt as kerb_tgt_mod
    monkeypatch.setattr(kerb_tgt_mod, "inline_tgt_ccache", fake_inline)

    _invoke_run_cli(ns, monkeypatch)

    assert seen["lm_hash"] is None
    assert seen["nt_hash"] == "31d6cfe0d16ae931b73c59d7e0c089c0"


def test_dispatch_falls_back_to_system_ccache_with_kerberos_flag(monkeypatch):
    ns = _base_options(
        connection="jjk.local/yuji@dc-curse.jjk.local",  # no password
        enroll_ws=True,
        kerberos=True,
    )

    from src import cert_enroll_wstep as wstep_mod
    monkeypatch.setattr(wstep_mod, "run_enroll", lambda **_: None)

    called = {"n": 0}

    @contextlib.contextmanager
    def fake_inline(**kw):
        called["n"] += 1
        yield "/should/not/be/used"

    from src import kerb_tgt as kerb_tgt_mod
    monkeypatch.setattr(kerb_tgt_mod, "inline_tgt_ccache", fake_inline)

    # When -k is passed and no CLI password, we expect the system ccache
    # path (nullcontext). ``parse_target`` returns no password so the
    # dispatch picks nullcontext regardless.
    _invoke_run_cli(ns, monkeypatch)
    assert called["n"] == 0


def test_dispatch_uses_inline_tgt_for_list_policies(monkeypatch):
    ns = _base_options(list_policies_ws=True)

    from src import cert_enroll_xcep as xcep_mod
    monkeypatch.setattr(xcep_mod, "run_list_policies", lambda **_: None)

    called = {"n": 0}

    @contextlib.contextmanager
    def fake_inline(**kw):
        called["n"] += 1
        yield "/fake"

    from src import kerb_tgt as kerb_tgt_mod
    monkeypatch.setattr(kerb_tgt_mod, "inline_tgt_ccache", fake_inline)

    _invoke_run_cli(ns, monkeypatch)
    assert called["n"] == 1
