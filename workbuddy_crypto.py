"""
workbuddy_crypto.py — 新版 WorkBuddy AI 海外客户端静态加密解密

背景（逆向自 WorkBuddy AI.app asar → main/credential-protection.js、
main/process-cpu-sampler.js、Electron Framework electron_api_workbuddy_storage.cc）：

信封结构（字段级，"$wbEncrypted" 包裹）：
    envelope_b64 解开 = {"suite":1,"keyId":…,"nonce":…,"authTag":…,"ciphertext":…}
    - nonce:    base64 12 字节 IV
    - authTag:  base64 16 字节 GCM tag
    - 算法:     AES-256-GCM

密钥链：
    1. 主进程 native binding `electron_browser_workbuddy_storage.loggerGet()`
       返回 build-key payload JSON: {"version":1,"atRestSecretKey":"<44位canonical b64>",…}
       （macOS 上 payload 由 data-protection Keychain 中 ACL 锁定到客户端进程的
         条目 + safeStorage 保护，文件系统上没有明文）
    2. protector key = sha256(atRestSecretKey 的 base64字符串, utf8)  → 32 字节
       protector keyId  = sha256(protectorKey).hex[:16]
       keyId 是密钥指纹（不可反推 key），解密前必须与 envelope.keyId 一致
    3. 字段加密直接用 protector key（keyblob 主密钥仅用于 asym-v1 文件链路）

AAD（sym-v1 分支，buildAuthenticatedContextAad）：
    b"WB-AAD\\0" + 0x01
    + len_prefix(STANDARD_FORMAT_ID[framing])   # file="WBEF1" / field="WBEV1"
    + len_prefix("sym-v1")
    + u32_be(suite)
    + len_prefix(keyId)                          # keyId 以 hex 字符串参与
    + u8(FRAMING_CODE[framing])                  # file=1 / field=2
    + 0x00（sequence 无） + 0x00（final 未定义）
    其中 field 的 fieldPath（JSON Pointer，如 /auth/accessToken）不直接进 AAD，
    但 purpose/resourceId/fieldPath 由应用层在 seal/open 时保持一致；
    sym-v1 字段链路的 AAD 只包含上述字段（已在真机验证）。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Optional

CRYPTO_UNAVAILABLE = "crypto_unavailable"

# macOS 客户端可执行与 inspector 端口
_MAC_APP_BIN = "/Applications/WorkBuddy AI.app/Contents/MacOS/Electron"
_INSPECT_PORT = 9231

# buildkey 缓存（与网关数据库同目录，0600）
_BUILDKEY_CACHE_ENV = "CB_WB_BUILDKEY_FILE"
_BUILDKEY_CACHE_NAME = "workbuddy.buildkey.json"


class WorkBuddyCryptoError(Exception):
    def __init__(self, message: str, category: str = "unknown"):
        super().__init__(message)
        self.category = category


# ============================================================
# AAD 与 GCM
# ============================================================

_AAD_DOMAIN = b"WB-AAD\x00"
_FORMAT_ID = {"file": b"WBEF1", "field": b"WBEV1"}
_FRAMING_CODE = {"file": 1, "field": 2}


def _u32be(value: int) -> bytes:
    return struct.pack(">I", value)


def _len_prefixed(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _u32be(len(raw)) + raw


def build_aad_sym_v1(key_id: str, framing: str, suite: int = 1) -> bytes:
    if framing not in _FRAMING_CODE:
        raise WorkBuddyCryptoError(f"unsupported framing: {framing}", "unsupported")
    return b"".join([
        _AAD_DOMAIN,
        b"\x01",
        _len_prefixed(_FORMAT_ID[framing].decode()),
        _len_prefixed("sym-v1"),
        _u32be(suite),
        _len_prefixed(key_id),
        bytes([_FRAMING_CODE[framing]]),
        b"\x00",  # sequence: 无
        b"\x00",  # final: undefined
    ])


def derive_protector(at_rest_secret_key_b64: str) -> tuple[bytes, str]:
    """sha256(atRestSecretKey 字符串 utf8) → (32B key, 16位hex keyId)"""
    key = hashlib.sha256(at_rest_secret_key_b64.encode("utf-8")).digest()
    key_id = hashlib.sha256(key).hexdigest()[:16]
    return key, key_id


def open_envelope(key: bytes, envelope: dict, framing: str) -> bytes:
    """AES-256-GCM 解开 envelope，framing 为 'file' 或 'field'。"""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key_id = str(envelope.get("keyId", ""))
    suite = int(envelope.get("suite", 1))
    nonce = base64.b64decode(envelope.get("nonce", ""))
    auth_tag = base64.b64decode(envelope.get("authTag", ""))
    ciphertext = base64.b64decode(envelope.get("ciphertext", ""))
    if len(nonce) != 12:
        raise WorkBuddyCryptoError(f"nonce 长度异常: {len(nonce)}", "integrity")
    if len(auth_tag) != 16:
        raise WorkBuddyCryptoError(f"authTag 长度异常: {len(auth_tag)}", "integrity")
    aad = build_aad_sym_v1(key_id, framing, suite)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext + auth_tag, aad)
    except Exception as exc:  # InvalidTag 等
        raise WorkBuddyCryptoError(f"GCM 认证失败: {exc}", "integrity") from exc


def seal_field(key: bytes, key_id: str, plaintext: bytes, framing: str = "field", suite: int = 1) -> dict:
    """与客户端同格式的加密封装（测试/验证用）。"""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = os.urandom(12)
    aad = build_aad_sym_v1(key_id, framing, suite)
    sealed = AESGCM(key).encrypt(nonce, plaintext, aad)
    return {
        "suite": suite,
        "keyId": key_id,
        "nonce": base64.b64encode(nonce).decode(),
        "authTag": base64.b64encode(sealed[-16:]).decode(),
        "ciphertext": base64.b64encode(sealed[:-16]).decode(),
    }


# ============================================================
# buildkey payload 获取
# ============================================================

def buildkey_cache_path() -> Optional[Path]:
    configured = os.environ.get(_BUILDKEY_CACHE_ENV, "").strip()
    if configured:
        return Path(configured).expanduser()
    try:
        import database as db
        return db.DB_PATH.parent / _BUILDKEY_CACHE_NAME
    except Exception:
        return None


def load_cached_buildkey() -> Optional[dict]:
    """读取缓存的 build-key payload。"""
    candidates = []
    configured = os.environ.get("CB_WB_BUILDKEY", "").strip()
    if configured:
        candidates.append(Path(configured).expanduser())
    cache = buildkey_cache_path()
    if cache:
        candidates.append(cache)
    for path in candidates:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(payload, dict) and payload.get("atRestSecretKey"):
            return payload
    return None


def save_buildkey_cache(payload: dict) -> Optional[Path]:
    cache = buildkey_cache_path()
    if not cache:
        return None
    try:
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        os.chmod(cache, 0o600)
        return cache
    except OSError:
        return None


def get_buildkey_payload(auto_extract: bool = True) -> Optional[dict]:
    """拿 build-key payload：先读缓存，缺失时在 macOS 上自动提取。"""
    payload = load_cached_buildkey()
    if payload:
        return payload
    if auto_extract and sys.platform == "darwin" and os.path.exists(_MAC_APP_BIN):
        try:
            payload = extract_buildkey_via_inspector()
        except (WorkBuddyCryptoError, OSError, ValueError):
            return None
        if payload:
            save_buildkey_cache(payload)
            return payload
    return None


def buildkey_status() -> dict:
    """缓存/提取可用性概况（不含密钥内容）。"""
    payload = load_cached_buildkey()
    if payload:
        try:
            key, key_id = derive_protector(str(payload["atRestSecretKey"]))
            return {"cached": True, "protector_key_id": key_id}
        except Exception:
            return {"cached": True, "protector_key_id": ""}
    can_extract = bool(sys.platform == "darwin" and os.path.exists(_MAC_APP_BIN))
    return {"cached": False, "can_extract": can_extract}


def ensure_buildkey() -> dict:
    """确保 build-key 缓存存在；缺失时在 macOS 上自动提取一次（会重启客户端）。

    返回 {"cached": bool, "extracted": bool, ...}，任何失败都不抛出。
    """
    result = {"cached": False, "extracted": False}
    payload = load_cached_buildkey()
    if payload:
        result["cached"] = True
        return result
    if sys.platform != "darwin" or not os.path.exists(_MAC_APP_BIN):
        result["error"] = "build-key 自动提取仅支持 macOS 上的本机 WorkBuddy AI 客户端"
        return result
    try:
        payload = extract_buildkey_via_inspector()
    except (WorkBuddyCryptoError, OSError, ValueError) as exc:
        result["error"] = str(exc)[:200]
        return result
    save_buildkey_cache(payload)
    result["cached"] = True
    result["extracted"] = True
    return result


# ============================================================
# macOS: 经 inspector 在 app 主进程内调 loggerGet()
# （让 app 用自己的 ACL 身份读钥匙串，无需抓包、无权限弹窗；
#   代价是首次提取时需要短暂重启一次客户端）
# ============================================================

def _ws_connect(host: str, port: int, path: str) -> socket.socket:
    sock = socket.create_connection((host, port), timeout=5)
    key = base64.b64encode(os.urandom(16)).decode()
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    )
    sock.sendall(request.encode())
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            raise WorkBuddyCryptoError("inspector websocket 握手失败", "transport")
        response += chunk
    status = response.split(b"\r\n", 1)[0]
    if b"101" not in status:
        raise WorkBuddyCryptoError(f"inspector websocket 握手被拒: {status!r}", "transport")
    return sock


def _ws_send(sock: socket.socket, payload: str) -> None:
    data = payload.encode()
    header = bytearray([0x81])  # FIN + text frame
    mask = os.urandom(4)
    length = len(data)
    if length < 126:
        header.append(0x80 | length)
    elif length < 65536:
        header.append(0x80 | 126)
        header += struct.pack(">H", length)
    else:
        header.append(0x80 | 127)
        header += struct.pack(">Q", length)
    header += mask
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    sock.sendall(bytes(header) + masked)


def _ws_recv(sock: socket.socket) -> str:
    def read_exact(n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise WorkBuddyCryptoError("inspector websocket 连接中断", "transport")
            buf += chunk
        return buf

    while True:
        b1, b2 = read_exact(2)
        opcode = b1 & 0x0F
        masked = b2 & 0x80
        length = b2 & 0x7F
        if length == 126:
            length = struct.unpack(">H", read_exact(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", read_exact(8))[0]
        mask = read_exact(4) if masked else b""
        payload = read_exact(length)
        if mask:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        if opcode == 0x8:  # close
            raise WorkBuddyCryptoError("inspector websocket 被关闭", "transport")
        if opcode == 0x9:  # ping → pong
            continue
        if opcode in (0x1, 0x2, 0x0):
            return payload.decode("utf-8", errors="replace")


def _inspect_eval(expr: str, timeout: float = 20.0) -> str:
    """连 inspector，Runtime.evaluate 并返回结果 value（字符串）。"""
    deadline = time.time() + timeout
    targets = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{_INSPECT_PORT}/json/list", timeout=2
            ) as resp:
                targets = json.loads(resp.read().decode())
            if targets:
                break
        except (OSError, ValueError):
            time.sleep(0.4)
    if not targets:
        raise WorkBuddyCryptoError("inspector 端口未就绪", "transport")

    target = next(
        (t for t in targets if t.get("webSocketDebuggerUrl")), None
    )
    if not target:
        raise WorkBuddyCryptoError("inspector 无可用调试目标", "transport")
    ws_url = target["webSocketDebuggerUrl"]
    path = ws_url.split(f"{_INSPECT_PORT}", 1)[1] or "/"
    sock = _ws_connect("127.0.0.1", _INSPECT_PORT, path)
    try:
        _ws_send(sock, json.dumps({
            "id": 1,
            "method": "Runtime.evaluate",
            "params": {"expression": expr, "returnByValue": True},
        }))
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise WorkBuddyCryptoError("inspector eval 超时", "timeout")
            sock.settimeout(remaining)
            message = json.loads(_ws_recv(sock))
            if message.get("id") != 1:
                continue
            result = message.get("result", {})
            if result.get("exceptionDetails"):
                raise WorkBuddyCryptoError(
                    f"loggerGet 调用失败: {json.dumps(result['exceptionDetails'])[:200]}",
                    "safe-storage",
                )
            value = result.get("result", {}).get("value")
            if not isinstance(value, str):
                raise WorkBuddyCryptoError("loggerGet 返回值不是字符串", "invalid-key")
            return value
    finally:
        try:
            sock.close()
        except OSError:
            pass


def extract_buildkey_via_inspector(skip_launch: bool = False) -> Optional[dict]:
    """重启客户端（--inspect）→ 主进程内取 loggerGet() → 还原启动。返回 payload dict。"""
    if sys.platform != "darwin":
        raise WorkBuddyCryptoError("inspector 提取仅支持 macOS", "unsupported")
    expr = 'process._linkedBinding("electron_browser_workbuddy_storage").loggerGet()'
    app_name = "WorkBuddy AI"

    def quit_app():
        subprocess.run(["osascript", "-e", f'tell application "{app_name}" to quit'],
                       capture_output=True, timeout=15)
        time.sleep(4)

    def open_app():
        subprocess.run(["open", "-a", app_name], capture_output=True, timeout=15)
        time.sleep(3)

    if not skip_launch:
        quit_app()

    try:
        child = subprocess.Popen(
            [_MAC_APP_BIN, f"--inspect={_INSPECT_PORT}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        try:
            raw = _inspect_eval(expr, timeout=40.0)
        finally:
            try:
                child.terminate()
            except OSError:
                pass
    finally:
        if not skip_launch:
            open_app()

    payload = json.loads(raw)
    if not isinstance(payload, dict) or not payload.get("atRestSecretKey"):
        raise WorkBuddyCryptoError("build-key payload 缺少 atRestSecretKey", "invalid-key")
    return payload


# ============================================================
# auth 文件解密入口
# ============================================================

def decrypt_auth_document(data: dict, buildkey: Optional[dict] = None) -> dict:
    """就地解密 auth 文档里的 $wbEncrypted 字段。

    buildkey 为 None 时只读缓存（auto_extract=False，绝不触发客户端重启）。
    成功：返回 {"ok": True, "decrypted": [JSON Pointer...]}
    失败：返回 {"ok": False, "error": ..., "category": ...}
    """
    if buildkey is None:
        buildkey = get_buildkey_payload(auto_extract=False)
    if not buildkey:
        return {
            "ok": False,
            "error": "缺少 build-key payload（首次需在 macOS 上以本机身份提取一次）",
            "category": "missing-key",
        }

    key, key_id = derive_protector(str(buildkey["atRestSecretKey"]))
    decrypted: list[str] = []

    def walk(node, pointer: str):
        if isinstance(node, list):
            for i, item in enumerate(node):
                walk(item, f"{pointer}/{i}")
            return
        if not isinstance(node, dict):
            return
        for field, value in list(node.items()):
            path = f"{pointer}/{field}"
            if (
                isinstance(value, dict)
                and "$wbEncrypted" in value
                and isinstance(value.get("envelope"), str)
            ):
                try:
                    envelope = json.loads(base64.b64decode(value["envelope"]).decode("utf-8"))
                except (ValueError, UnicodeDecodeError) as exc:
                    raise WorkBuddyCryptoError(f"envelope 解析失败 {path}: {exc}", "integrity") from exc
                if str(envelope.get("keyId")) != key_id:
                    raise WorkBuddyCryptoError(
                        f"keyId 不匹配 {path}: envelope={envelope.get('keyId')} protector={key_id}",
                        "key-mismatch",
                    )
                plaintext = open_envelope(key, envelope, "field")
                text = plaintext.decode("utf-8")
                try:
                    node[field] = json.loads(text)
                except ValueError:
                    node[field] = text
                decrypted.append(path)
            else:
                walk(value, path)

    try:
        walk(data, "")
    except WorkBuddyCryptoError as exc:
        return {"ok": False, "error": str(exc), "category": exc.category}
    return {"ok": True, "decrypted": decrypted}
