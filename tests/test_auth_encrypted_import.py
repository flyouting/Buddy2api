"""新版 WorkBuddy 客户端 $wbEncrypted 加密 auth 文件的导入行为测试。

- 伪造/损坏 envelope：仍拒绝导入，但 reason 指向解密失败
- 真实格式 envelope + 自造 buildkey：应解密出明文 token 并正常入库
"""

import base64
import json

import pytest

import auth_manager
import credential_crypto
import workbuddy_crypto
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


def _invalid_envelope():
    return {"$wbEncrypted": 1, "envelope": "eyJzdWl0ZSI6MX0="}


# ============================================================
# 损坏 envelope：仍然拒绝
# ============================================================

def test_scan_flags_broken_encrypted_file_as_not_importable(tmp_path):
    info = _write_info(tmp_path / "enc.info", _invalid_envelope())
    meta = auth_manager._safe_auth_file_meta(info, set())
    assert not meta["valid"]
    assert ("$wbEncrypted" in meta["reason"]) or ("解密失败" in meta["reason"])


def test_parse_auth_file_rejects_broken_encrypted_file(tmp_path):
    info = _write_info(tmp_path / "enc.info", _invalid_envelope())
    assert auth_manager.parse_auth_file(info) is None


def test_import_auth_file_skips_broken_encrypted_without_crash(isolated_db, tmp_path):
    info = _write_info(tmp_path / "enc.info", _invalid_envelope())
    assert auth_manager.import_auth_file(info) is None
    assert db.list_accounts() == []


def test_auto_scan_skips_broken_encrypted_file(isolated_db, tmp_path, monkeypatch):
    info = _write_info(tmp_path / "enc.info", _invalid_envelope())
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


# ============================================================
# 真实 envelope + 自造 buildkey：应解密并入库
# ============================================================

pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead", reason="cryptography 未安装")


@pytest.fixture()
def synthetic_buildkey(monkeypatch):
    """自造 atRestSecretKey → protector key；屏蔽提取与真机缓存。"""
    secret = "c2ludGhldGljLXRlc3Qta2V5LWZvci1idWRkeTJhcGktdGVzdHM="  # 44 位 canonical base64
    payload = {"version": 1, "atRestSecretKey": secret}
    monkeypatch.setattr(
        workbuddy_crypto, "get_buildkey_payload", lambda auto_extract=True: payload
    )
    return payload


def _wrap(key, key_id, plaintext: bytes) -> dict:
    envelope = workbuddy_crypto.seal_field(key, key_id, plaintext, framing="field")
    return {
        "$wbEncrypted": 1,
        "envelope": base64.b64encode(json.dumps(envelope).encode()).decode(),
    }


def test_roundtrip_field_envelope_decrypts(tmp_path, synthetic_buildkey):
    key, key_id = workbuddy_crypto.derive_protector(synthetic_buildkey["atRestSecretKey"])
    doc = {
        "account": {
            "uid": "u-enc",
            "nickname": _wrap(key, key_id, json.dumps({"nick": "enc-user"}).encode()),
        },
        "auth": {
            "accessToken": _wrap(key, key_id, b"plain-access-token"),
            "refreshToken": "ref-token",
        },
    }
    info = tmp_path / "enc.info"
    info.write_text(json.dumps(doc), encoding="utf-8")

    parsed = auth_manager.parse_auth_file(info)
    assert parsed is not None
    assert parsed["access_token"] == "plain-access-token"
    assert parsed["refresh_token"] == "ref-token"
    assert parsed["name"] == "enc-user"


def test_roundtrip_imports_into_db(tmp_path, synthetic_buildkey, isolated_db):
    key, key_id = workbuddy_crypto.derive_protector(synthetic_buildkey["atRestSecretKey"])
    doc = {
        "account": {"uid": "u-enc", "nickname": "enc-user"},
        "auth": {"accessToken": _wrap(key, key_id, b"plain-access-token")},
    }
    info = tmp_path / "enc.info"
    info.write_text(json.dumps(doc), encoding="utf-8")

    aid = auth_manager.import_auth_file(info)
    assert aid is not None
    accounts = db.list_accounts()
    assert len(accounts) == 1
    # 数据库凭据字段是加密存储的，读回应还原明文
    assert accounts[0]["access_token"] == "plain-access-token"


def test_key_id_mismatch_is_rejected(tmp_path, synthetic_buildkey):
    key, key_id = workbuddy_crypto.derive_protector(synthetic_buildkey["atRestSecretKey"])
    wrong_id = "0" * 16
    assert wrong_id != key_id
    envelope = workbuddy_crypto.seal_field(key, key_id, b"x", framing="field")
    envelope["keyId"] = wrong_id
    doc = {
        "auth": {
            "accessToken": {
                "$wbEncrypted": 1,
                "envelope": base64.b64encode(json.dumps(envelope).encode()).decode(),
            }
        }
    }
    info = tmp_path / "enc.info"
    info.write_text(json.dumps(doc), encoding="utf-8")
    meta = auth_manager._safe_auth_file_meta(info, set())
    assert not meta["valid"]
    assert "key-mismatch" in meta["reason"]
