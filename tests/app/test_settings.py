from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from ciso.app.settings import ExternalInferenceSettings, SafetySettings, Settings, load_settings
from ciso.common.enums import Role
from ciso.common.errors import ValidationFailed

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
PROVISIONAL = REPO_ROOT / "config" / "provisional-settings.json"


class TestDefaultsRefuse:
    def test_every_safety_number_is_unset_by_default(self) -> None:
        safety = SafetySettings()
        numeric = {
            name: value
            for name, value in safety.model_dump().items()
            if name != "allow_self_approval"
        }
        assert numeric, "no safety parameters found"
        assert all(value is None for value in numeric.values()), numeric

    def test_self_approval_is_off_by_default(self) -> None:
        assert SafetySettings().allow_self_approval is False

    def test_external_inference_is_off_and_unusable_by_default(self) -> None:
        external = Settings().external_inference
        assert external.enabled is False
        assert external.approver_role is None
        assert external.allowed_classifications == ()
        assert external.usable is False

    def test_enabling_alone_does_not_make_external_inference_usable(self) -> None:
        assert ExternalInferenceSettings(enabled=True).usable is False
        assert (
            ExternalInferenceSettings(enabled=True, approver_role=Role.SYSTEM_OWNER).usable is False
        )
        assert ExternalInferenceSettings(
            enabled=True, approver_role=Role.SYSTEM_OWNER, allowed_classifications=("a",)
        ).usable

    def test_external_approver_cannot_be_a_non_human_role(self) -> None:
        with pytest.raises(ValidationError, match="human-only"):
            ExternalInferenceSettings(approver_role=Role.EMPLOYEE)

    def test_external_approver_cannot_be_the_read_only_auditor(self) -> None:
        with pytest.raises(ValidationError, match="read-only"):
            ExternalInferenceSettings(approver_role=Role.AUDITOR)
        for role in (Role.SYSTEM_OWNER, Role.EXECUTIVE_RISK_OWNER):
            assert ExternalInferenceSettings(approver_role=role).approver_role is role

    def test_defaults_bind_loopback_and_have_no_classification_scheme(self) -> None:
        settings = load_settings(None)
        assert settings.bind_host == "127.0.0.1"
        assert settings.classification is None
        assert "audit_hmac_key_ref" in settings.missing_for_writes()
        assert "safety.max_envelope_ttl_seconds" in settings.missing_for_writes()


class TestValidation:
    def test_non_loopback_bind_needs_an_explicit_decision(self) -> None:
        with pytest.raises(ValidationError, match="not loopback"):
            Settings(bind_host="0.0.0.0")  # noqa: S104
        assert Settings(bind_host="10.0.0.5", allow_non_loopback_bind=True).bind_host == "10.0.0.5"

    def test_key_settings_must_be_references(self) -> None:
        with pytest.raises(ValidationError, match="secret://"):
            Settings(audit_hmac_key_ref="hunter2-not-a-ref")

    def test_backoff_and_freshness_bounds_are_checked(self) -> None:
        with pytest.raises(ValidationError, match="backoff"):
            SafetySettings(queue_backoff_base_seconds=10, queue_backoff_max_seconds=5)
        with pytest.raises(ValidationError, match="freshness"):
            SafetySettings(fact_freshness_seconds=10, fact_expiry_seconds=5)

    @pytest.mark.parametrize("value", [0, -1])
    def test_non_positive_numbers_are_rejected(self, value: int) -> None:
        with pytest.raises(ValidationError):
            SafetySettings(queue_max_attempts=value)

    def test_external_classifications_must_exist_in_the_scheme(self) -> None:
        with pytest.raises(ValidationError, match="no scheme"):
            Settings(external_inference=ExternalInferenceSettings(allowed_classifications=("a",)))
        with pytest.raises((ValidationError, ValidationFailed)):
            Settings(
                classification_labels=("a", "b"),
                external_inference=ExternalInferenceSettings(allowed_classifications=("zzz",)),
            )

    def test_audit_anchor_lives_outside_the_audit_database(self) -> None:
        settings = Settings()
        assert settings.audit_anchor.parent != settings.audit_db.parent
        assert settings.audit_db != settings.operational_db


class TestLoading:
    def test_misspelt_key_is_an_error(self, tmp_path: Path) -> None:
        file = tmp_path / "s.json"
        file.write_text(json.dumps({"safety": {"max_tokn_ttl_seconds": 5}}), encoding="utf-8")
        with pytest.raises(ValidationFailed, match="invalid settings"):
            load_settings(file)

    def test_missing_and_malformed_files_are_errors(self, tmp_path: Path) -> None:
        with pytest.raises(ValidationFailed, match="not found"):
            load_settings(tmp_path / "absent.json")
        bad = tmp_path / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        with pytest.raises(ValidationFailed, match="not valid JSON"):
            load_settings(bad)
        array = tmp_path / "array.json"
        array.write_text("[]", encoding="utf-8")
        with pytest.raises(ValidationFailed, match="JSON object"):
            load_settings(array)

    def test_provisional_file_loads_and_keeps_external_inference_off(self) -> None:
        settings = load_settings(PROVISIONAL)
        assert settings.missing_for_writes() == []
        assert settings.external_inference.usable is False
        assert settings.safety.allow_self_approval is False
        assert settings.classification is not None
        unset = [name for name, value in settings.safety.model_dump().items() if value is None]
        assert unset == []

    def test_provisional_file_holds_no_secret_values(self) -> None:
        raw = json.loads(PROVISIONAL.read_text(encoding="utf-8"))
        for name in (
            "audit_hmac_key_ref",
            "killswitch_key_ref",
            "evidence_key_ref",
            "backup_key_ref",
        ):
            assert raw[name].startswith("secret://")
        assert "PROVISIONAL" in raw["_comment"]

    def test_anchor_under_the_data_directory_is_reported(self, tmp_path: Path) -> None:
        default = Settings()
        assert default.audit_anchor_is_isolated is False
        assert any("anchor" in warning for warning in default.integrity_warnings())
        assert any("witness" in warning for warning in default.integrity_warnings())
        isolated = Settings(
            audit_anchor_path=tmp_path / "elsewhere" / "head.json",
            audit_witness_path=tmp_path / "witness" / "heads.jsonl",
            audit_witness_key_ref="secret://audit_witness_key",
            safety=SafetySettings(audit_witness_every=1),
        )
        assert isolated.audit_anchor == tmp_path / "elsewhere" / "head.json"
        assert isolated.integrity_warnings() == []

    def test_witness_path_without_key_or_cadence_is_reported(self, tmp_path: Path) -> None:
        half = Settings(
            audit_anchor_path=tmp_path / "a" / "head.json",
            audit_witness_path=tmp_path / "w" / "heads.jsonl",
        )
        assert any("key or cadence" in warning for warning in half.integrity_warnings())
        full = Settings(
            audit_anchor_path=tmp_path / "a" / "head.json",
            audit_witness_path=tmp_path / "w" / "heads.jsonl",
            audit_witness_key_ref="secret://audit_witness_key",
            safety=SafetySettings(audit_witness_every=1),
        )
        assert full.integrity_warnings() == []
        with pytest.raises(ValidationError, match="secret://"):
            Settings(audit_witness_key_ref="not-a-ref")
