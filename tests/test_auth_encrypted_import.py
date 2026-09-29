import json

import pytest

import auth_manager
import credential_crypto
import database as db


@pytest.fixture()
def isolated_db(tmp_path, monkeypatch):
    path = tmp_path / "gateway.db"
    monkeypatch.setattr(db, "DB_PATH", path)
    monkeypatch.setenv("CB_GATEWAY_MASTER_KEY", "pytest-master-key")
    credential_crypto.reset_cache()
    db.init_db()
    yield path
    credential_crypto.reset_cache()


def _write_info(path, access_token, refresh_token="ref-token"):
    data = {
        "account": {"uid": "u-enc", "nickname": "enc-user"},
        "auth": {"accessToken": access_token, "refreshToken": refresh_token},
    }
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _encrypted_token():
    return {"$wbEncrypted": 1, "envelope": "eyJzdWl0ZSI6MX0="}


def test_scan_flags_encrypted_file_as_not_importable(tmp_path):
    info = _write_info(tmp_path / "enc.info", _encrypted_token())
    meta = auth_manager._safe_auth_file_meta(info, set())
    assert not meta["valid"]
    assert "$wbEncrypted" in meta["reason"]


def test_parse_auth_file_rejects_encrypted_file(tmp_path):
    info = _write_info(tmp_path / "enc.info", _encrypted_token())
    assert auth_manager.parse_auth_file(info) is None


def test_import_auth_file_skips_encrypted_without_crash(isolated_db, tmp_path):
    info = _write_info(tmp_path / "enc.info", _encrypted_token())
    assert auth_manager.import_auth_file(info) is None
    assert db.list_accounts() == []


def test_auto_scan_skips_encrypted_file(isolated_db, tmp_path, monkeypatch):
    info = _write_info(tmp_path / "enc.info", _encrypted_token())
    monkeypatch.setattr(auth_manager, "find_auth_files", lambda auth_dir=None: [info])
    result = auth_manager.auto_scan_and_import()
    assert result["imported"] == 0
    assert result["updated"] == 0
    assert result["skipped"] == 1
    assert result["errors"] == []


def test_plaintext_file_still_imports(isolated_db, tmp_path, monkeypatch):
    info = _write_info(tmp_path / "plain.info", "plain-token")
    monkeypatch.setattr(auth_manager, "find_auth_files", lambda auth_dir=None: [info])
    result = auth_manager.auto_scan_and_import()
    assert result["imported"] == 1
    accounts = db.list_accounts()
    assert len(accounts) == 1
    assert accounts[0]["uid"] == "u-enc"
