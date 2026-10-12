"""Tests for the HWI bond signing script helpers."""

from __future__ import annotations

import sys
from base64 import b64encode
from pathlib import Path
from unittest.mock import Mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from sign_bond_psbt import (
    enumerate_devices,
    is_stable_package_release,
    jade_cbor2_error,
    jade_cbor2_warning,
    jade_cbor_transport_error_hint,
    main,
    outdated_hwi_hint,
    parse_hwi_version,
)


class TestParseHwiVersion:
    @pytest.mark.parametrize(
        ("version", "expected"),
        [
            ("3.1.0", (3, 1, 0)),
            ("2.4.0", (2, 4, 0)),
            ("3.1.0.dev1", (3, 1, 0)),
            (" 3.2.1 ", (3, 2, 1)),
            ("10.0.5", (10, 0, 5)),
        ],
    )
    def test_valid_versions(self, version: str, expected: tuple[int, int, int]) -> None:
        assert parse_hwi_version(version) == expected

    @pytest.mark.parametrize("version", ["", "abc", "3.1", "v3.1.0", "3"])
    def test_invalid_versions(self, version: str) -> None:
        assert parse_hwi_version(version) is None


class TestOutdatedHwiHint:
    def test_no_hint_for_recent_versions(self) -> None:
        assert outdated_hwi_hint("3.1.0") is None
        assert outdated_hwi_hint("3.2.0") is None
        assert outdated_hwi_hint("4.0.0") is None

    @pytest.mark.parametrize("version", ["3.0.0", "2.4.0", "2.1.1", "1.2.1"])
    def test_hint_for_old_versions(self, version: str) -> None:
        hint = outdated_hwi_hint(version)
        assert hint is not None
        assert version in hint
        assert "3.1.0" in hint
        assert "pip install -U hwi" in hint
        # The hint must name the affected newer devices (see issue #552).
        assert "Ledger Stax/Flex" in hint

    def test_hint_for_unknown_version(self) -> None:
        hint = outdated_hwi_hint(None)
        assert hint is not None
        assert "pip install -U hwi" in hint

    def test_hint_for_unparseable_version(self) -> None:
        hint = outdated_hwi_hint("weird")
        assert hint is not None
        assert "pip install -U hwi" in hint


class TestJadeCborCompatibility:
    def test_cbor_580_is_blocked(self) -> None:
        error = jade_cbor2_error("5.8.0")

        assert error is not None
        assert "incompatible with Jade" in error
        assert "issues/817" in error
        assert "5.9.0" in error

    @pytest.mark.parametrize(
        "version", ["5.7.1", "5.8.0.post1", "5.9.0", "6.0.0", None, "unknown"]
    )
    def test_other_cbor_versions_are_not_blocked(self, version: str | None) -> None:
        assert jade_cbor2_error(version) is None

    def test_old_cbor_version_warns(self) -> None:
        warning = jade_cbor2_warning("5.7.1")

        assert warning is not None
        assert "security issues" in warning
        assert "pull/832" in warning

    def test_secure_cbor_version_has_no_warning(self) -> None:
        assert jade_cbor2_warning("5.9.0") is None

    @pytest.mark.parametrize("version", ["5.9.0rc1", "5.9.0.dev1"])
    def test_prerelease_cbor_version_warns(self, version: str) -> None:
        warning = jade_cbor2_warning(version)

        assert warning is not None
        assert "secure 5.9.0 release" in warning

    @pytest.mark.parametrize(
        ("version", "expected"),
        [("5.9.0", True), ("5.9.0.post1", True), ("5.9.0rc1", False), ("bad", False)],
    )
    def test_stable_release_detection(self, version: str, expected: bool) -> None:
        assert is_stable_package_release(version) is expected

    def test_unknown_cbor_version_warns(self) -> None:
        warning = jade_cbor2_warning(None)

        assert warning is not None
        assert "Could not determine" in warning


class TestJadeCborTransportErrorHint:
    @pytest.mark.parametrize(
        "error",
        [
            ValueError("error decoding unicode string"),
            RuntimeError("CBORDecodeValueError while reading response"),
        ],
    )
    def test_jade_decode_error_explains_recovery(self, error: Exception) -> None:
        hint = jade_cbor_transport_error_hint("jade", error, "5.8.0")

        assert hint is not None
        assert "No signed PSBT was" in hint
        assert "retry" in hint
        assert "5.8.0" in hint

    def test_non_jade_error_is_not_misclassified(self) -> None:
        error = ValueError("error decoding unicode string")
        assert jade_cbor_transport_error_hint("ledger", error, "5.8.0") is None

    def test_unrelated_jade_error_is_not_misclassified(self) -> None:
        assert (
            jade_cbor_transport_error_hint("jade", OSError("USB unplugged"), "5.9.0")
            is None
        )


class TestMainJadeCborHandling:
    PSBT = b64encode(b"psbt\xff").decode()
    JADE = {"type": "jade", "path": "/dev/ttyUSB0", "fingerprint": "73c5da0a"}

    def _patch_environment(
        self, monkeypatch: pytest.MonkeyPatch, cbor2_version: str, sign_psbt: Mock
    ) -> None:
        monkeypatch.setattr(
            sys, "argv", ["sign_bond_psbt.py", self.PSBT, "--chain", "main"]
        )
        monkeypatch.setattr("sign_bond_psbt.check_hwi_installed", lambda: None)
        monkeypatch.setattr("sign_bond_psbt.get_installed_hwi_version", lambda: "3.2.0")
        monkeypatch.setattr(
            "sign_bond_psbt.get_installed_package_version",
            lambda _package: cbor2_version,
        )
        monkeypatch.setattr(
            "sign_bond_psbt.enumerate_devices",
            lambda _device_type, password=None: [self.JADE],
        )
        monkeypatch.setattr("sign_bond_psbt.sign_psbt", sign_psbt)

    def test_cbor_580_stops_before_device_signing(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        sign_psbt = Mock()
        self._patch_environment(monkeypatch, "5.8.0", sign_psbt)
        enumerate_devices = Mock(return_value=[self.JADE])
        monkeypatch.setattr("sign_bond_psbt.enumerate_devices", enumerate_devices)

        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 1
        enumerate_devices.assert_not_called()
        sign_psbt.assert_not_called()
        stderr = capsys.readouterr().err
        assert "cbor2 version: 5.8.0" in stderr
        assert "incompatible with Jade" in stderr

    def test_decode_failure_reports_transport_recovery(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        sign_psbt = Mock(side_effect=ValueError("error decoding unicode string"))
        self._patch_environment(monkeypatch, "5.9.0", sign_psbt)

        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 1
        sign_psbt.assert_called_once()
        stderr = capsys.readouterr().err
        assert "No signed PSBT was" in stderr
        assert "retry" in stderr

    def test_bitbox_password_is_prompted_and_forwarded(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        bitbox = {
            "type": "digitalbitbox",
            "path": "0001:0002:00",
            "fingerprint": "73c5da0a",
        }
        enumerate_devices = Mock(return_value=[bitbox])
        sign_psbt = Mock(return_value={"psbt": "signed-psbt", "signed": True})
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "sign_bond_psbt.py",
                self.PSBT,
                "--device-type",
                "digitalbitbox",
                "--device-password",
                "--no-broadcast",
                "--chain",
                "main",
            ],
        )
        monkeypatch.setattr("sign_bond_psbt.check_hwi_installed", lambda: None)
        monkeypatch.setattr("sign_bond_psbt.get_installed_hwi_version", lambda: "3.2.0")
        monkeypatch.setattr(
            "sign_bond_psbt.get_installed_package_version", lambda _package: "5.9.0"
        )
        monkeypatch.setattr(
            "sign_bond_psbt.getpass.getpass", lambda _prompt: "test-password"
        )
        monkeypatch.setattr("sign_bond_psbt.enumerate_devices", enumerate_devices)
        monkeypatch.setattr("sign_bond_psbt.sign_psbt", sign_psbt)

        main()

        enumerate_devices.assert_called_once_with(
            "digitalbitbox", password="test-password"
        )
        sign_psbt.assert_called_once_with(
            bitbox,
            self.PSBT,
            chain="main",
            password="test-password",
        )
        assert capsys.readouterr().out.strip() == "signed-psbt"

    def test_unchanged_psbt_is_not_reported_as_signed(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        sign_psbt = Mock(return_value={"psbt": self.PSBT, "signed": False})
        self._patch_environment(monkeypatch, "5.9.0", sign_psbt)

        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 1
        assert "without adding a signature" in capsys.readouterr().err


class TestDeviceSpecificEnumeration:
    def test_explicit_bitbox_does_not_use_global_enumeration(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        bitbox = {
            "type": "digitalbitbox",
            "model": "digitalbitbox_01",
            "path": "0001:0002:00",
        }
        module_enumerate = Mock(return_value=[bitbox])
        device_module = Mock(enumerate=module_enumerate)
        import_module = Mock(return_value=device_module)
        monkeypatch.setattr("sign_bond_psbt.importlib.import_module", import_module)

        devices = enumerate_devices("digitalbitbox", password="test-password")

        import_module.assert_called_once_with("hwilib.devices.digitalbitbox")
        module_enumerate.assert_called_once_with(password="test-password")
        assert devices == [bitbox]

    def test_unknown_device_module_returns_no_devices(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "sign_bond_psbt.importlib.import_module",
            Mock(side_effect=ImportError("unknown device")),
        )

        assert enumerate_devices("unknown") == []

    def test_model_selection_filters_other_models(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        safe3 = {"type": "trezor", "model": "trezor_safe3", "path": "safe3"}
        model_t = {"type": "trezor", "model": "trezor_t", "path": "model-t"}
        device_module = Mock(enumerate=Mock(return_value=[safe3, model_t]))
        monkeypatch.setattr(
            "sign_bond_psbt.importlib.import_module", Mock(return_value=device_module)
        )

        assert enumerate_devices("trezor_safe3") == [safe3]
