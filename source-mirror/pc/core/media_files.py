"""PMVE image and attachment access shared with the desktop UI."""

from __future__ import annotations

import base64
import hashlib
import io
import os
import shutil
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import pmv_media_ref

# 单个媒体文件理论上限（1 TiB）：PMVE 媒体流式写入容器 Object，仅受磁盘空间约束。
MAX_MEDIA_BYTES = 1024 * 1024 * 1024 * 1024
_CHUNK = 1024 * 1024

_MAGIC = b"VMED"
_MEDIA_VERSION = 0x01
_MEDIA_INFO = b"vault-media-v1"
_NONCE_LEN = 12
_HEADER_LEN = len(_MAGIC) + 1 + _NONCE_LEN  # 4 + 1 + 12 = 17
_TAG_LEN = 16


@dataclass(frozen=True, slots=True)
class _MediaContext:
    vault_id: str | None = None
    dek: bytes | None = None
    vault: object | None = None


_context_stack: list[_MediaContext] = []


class _VerifyingWriter:
    """Forward-only writer that verifies a streamed PMVE object's metadata."""

    def __init__(self, output) -> None:
        self._output = output
        self.size = 0
        self.digest = hashlib.sha256()

    def write(self, value: bytes) -> int:
        written = self._output.write(value)
        if written is None:
            written = len(value)
        if written != len(value):
            raise OSError("媒体导出发生短写")
        self.size += written
        self.digest.update(value)
        return written


def _verify_stream(ref: pmv_media_ref.MediaRef, writer: _VerifyingWriter) -> None:
    if writer.size != ref.size or writer.digest.digest() != ref.sha256:
        raise ValueError("PMVE 媒体对象完整性不匹配")


def set_media_context(vault_id: str, dek: bytes) -> None:
    """解锁后设置当前库的媒体加密上下文。

    使用栈：临时库（同步/外部读取）开库时 push，关库时 pop，不覆盖主库上下文。
    """
    global _context_stack
    if not vault_id or not dek:
        raise ValueError("媒体上下文需要 vault_id 与 DEK")
    _context_stack.append(_MediaContext(vault_id=vault_id, dek=bytes(dek)))


def set_vault_context(vault: object) -> None:
    """Push an unlocked PMVE Vault facade used for ObjectRef reads."""
    if vault is None:
        raise ValueError("媒体上下文需要已解锁的密码库")
    _context_stack.append(_MediaContext(vault=vault))


def set_vault_context_if_absent(vault: object) -> None:
    candidate = _MediaContext(vault=vault)
    if _context_stack and _context_stack[-1] == candidate:
        return
    set_vault_context(vault)


def ensure_vault_context(vault: object) -> None:
    """Make one unlocked PMVE Vault facade the active media context."""
    remove_vault_context(vault)
    set_vault_context(vault)


def remove_vault_context(vault: object) -> None:
    """Remove contexts owned by one Vault without popping unrelated callers."""
    global _context_stack
    _context_stack = [context for context in _context_stack if context.vault is not vault]


def clear_media_context() -> None:
    global _context_stack
    if _context_stack:
        _context_stack.pop()


def set_media_context_if_absent(vault_id: str, dek: bytes) -> None:
    """重锁恢复等场景：仅当栈顶不是该库时才入栈，避免重复。"""
    candidate = _MediaContext(vault_id=vault_id, dek=bytes(dek))
    if _context_stack and _context_stack[-1] == candidate:
        return
    set_media_context(vault_id, dek)


def _require_context() -> tuple[str, bytes]:
    if not _context_stack:
        raise RuntimeError("媒体未解锁，无法访问媒体文件")
    context = _context_stack[-1]
    if context.vault_id is None or context.dek is None:
        raise RuntimeError("当前媒体上下文不支持旧版外置文件")
    return context.vault_id, context.dek


def _require_vault_context() -> object:
    if not _context_stack or _context_stack[-1].vault is None:
        raise RuntimeError("媒体未解锁，无法访问 PMVE 对象")
    return _context_stack[-1].vault


def _active_vault_context() -> object | None:
    return _context_stack[-1].vault if _context_stack else None


def _media_key() -> bytes:
    _, dek = _require_context()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_MEDIA_INFO,
    ).derive(dek)


def _root() -> Path:
    vault_id, _ = _require_context()
    root = Path(os.environ.get("APPDATA", Path.home())) / "vault" / "media" / vault_id
    root.mkdir(parents=True, exist_ok=True)
    return root


def _kind_dir(kind: str) -> Path:
    directory = _root() / ("images" if kind == "image" else "attachments")
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _legacy_root() -> Path:
    return Path(os.environ.get("APPDATA", Path.home())) / "vault" / "media"


def _legacy_kind_dir(kind: str) -> Path:
    return _legacy_root() / ("images" if kind == "image" else "attachments")


def _encrypt(raw: bytes) -> bytes:
    """整块加密（内存版，用于小媒体）。"""
    nonce = os.urandom(_NONCE_LEN)
    encryptor = Cipher(algorithms.AES(_media_key()), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(_MEDIA_INFO)
    ct = encryptor.update(raw)
    encryptor.finalize()
    return _MAGIC + bytes([_MEDIA_VERSION]) + nonce + ct + encryptor.tag


def _decrypt(raw: bytes) -> bytes:
    """整块解密（内存版）。"""
    if not raw.startswith(_MAGIC) or len(raw) < _HEADER_LEN + _TAG_LEN:
        raise ValueError("媒体文件不是有效的加密格式")
    nonce = raw[_HEADER_LEN - _NONCE_LEN : _HEADER_LEN]
    body = raw[_HEADER_LEN:]
    tag = body[-_TAG_LEN:]
    ciphertext = body[:-_TAG_LEN]
    decryptor = Cipher(algorithms.AES(_media_key()), modes.GCM(nonce, tag)).decryptor()
    decryptor.authenticate_additional_data(_MEDIA_INFO)
    return decryptor.update(ciphertext) + decryptor.finalize()


def _encrypt_stream(input_handle, output_handle) -> None:
    """流式加密（用于大文件）。输出 MAGIC + version + nonce + ct + tag。"""
    nonce = os.urandom(_NONCE_LEN)
    encryptor = Cipher(algorithms.AES(_media_key()), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(_MEDIA_INFO)
    output_handle.write(_MAGIC)
    output_handle.write(bytes([_MEDIA_VERSION]))
    output_handle.write(nonce)
    while True:
        chunk = input_handle.read(_CHUNK)
        if not chunk:
            break
        output_handle.write(encryptor.update(chunk))
    encryptor.finalize()
    output_handle.write(encryptor.tag)


def _decrypt_stream(input_handle, output_handle) -> None:
    """流式解密（输入需可 seek，GCM tag 在文件末尾）。"""
    header = input_handle.read(_HEADER_LEN)
    if not header.startswith(_MAGIC) or len(header) < _HEADER_LEN:
        raise ValueError("媒体文件不是有效的加密格式")
    size = os.fstat(input_handle.fileno()).st_size
    input_handle.seek(size - _TAG_LEN)
    tag = input_handle.read(_TAG_LEN)
    input_handle.seek(_HEADER_LEN)
    nonce = header[_HEADER_LEN - _NONCE_LEN :]
    decryptor = Cipher(algorithms.AES(_media_key()), modes.GCM(nonce, tag)).decryptor()
    decryptor.authenticate_additional_data(_MEDIA_INFO)
    remaining = size - _HEADER_LEN - _TAG_LEN
    while remaining > 0:
        chunk = input_handle.read(min(_CHUNK, remaining))
        if not chunk:
            break
        remaining -= len(chunk)
        output_handle.write(decryptor.update(chunk))
    decryptor.finalize()


def _object_ref(value: object) -> pmv_media_ref.MediaRef | None:
    if isinstance(value, dict) and value.get(pmv_media_ref.TYPE_KEY) == pmv_media_ref.TYPE_VALUE:
        return pmv_media_ref.from_json(value)
    if isinstance(value, str) and value.startswith(pmv_media_ref.STRING_PREFIX):
        return pmv_media_ref.from_external_string(value)
    return None


def _is_legacy_ref(value: object) -> bool:
    return isinstance(value, str) and value.startswith(("img:", "att:"))


def is_ref(value: object) -> bool:
    if _is_legacy_ref(value):
        return True
    try:
        return _object_ref(value) is not None
    except (TypeError, ValueError):
        return False


def _decode_base64(value: str) -> bytes:
    """解码内联 base64，容忍换行等空白字符（旧格式常带换行）。"""
    if value.startswith("data:") and ";base64," in value:
        value = value.split(",", 1)[1]
    return base64.b64decode("".join(value.split()), validate=True)


def resolve_ref(value: object) -> Path | None:
    """把 img:/att: 引用解析为磁盘路径：优先当前库目录，回退旧全局目录（迁移源）。"""
    if not _is_legacy_ref(value):
        return None
    assert isinstance(value, str)
    prefix, name = value.split(":", 1)
    safe_name = Path(name).name
    if not safe_name or safe_name != name:
        return None
    kind = "image" if prefix == "img" else "attachment"
    primary = _kind_dir(kind) / safe_name
    if primary.is_file():
        return primary
    legacy = _legacy_kind_dir(kind) / safe_name
    if legacy.is_file():
        return legacy
    return None


def _image_extension(header: bytes) -> str:
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if header.startswith((b"GIF87a", b"GIF89a")):
        return ".gif"
    if header.startswith(b"RIFF") and header[8:12] == b"WEBP":
        return ".webp"
    if len(header) >= 12 and header[4:12] in (b"ftypheic", b"ftypheix", b"ftyphevc", b"ftyphevx"):
        return ".heic"
    return ".jpg"


def _safe_extension(kind: str, original_name: str, header: bytes) -> str:
    if kind == "image":
        return _image_extension(header)
    suffix = Path(original_name or "").suffix.lower()
    return suffix if 1 < len(suffix) <= 12 and suffix[1:].isalnum() else ".bin"


def import_file(source: Path, kind: str, original_name: str = "") -> str:
    """把源文件加密写入当前库媒体目录，返回 img:/att: 引用（内容寻址）。"""
    source = Path(source)
    if _active_vault_context() is not None:
        size = source.stat().st_size
        if size > MAX_MEDIA_BYTES:
            raise ValueError("媒体文件超过 1 TB 理论上限")
        return str(source.resolve())
    directory = _kind_dir(kind)
    digest = hashlib.sha256()
    header = b""
    fd, temporary_name = tempfile.mkstemp(prefix="import-", suffix=".tmp", dir=directory)
    os.close(fd)
    temporary = Path(temporary_name)
    try:
        with source.open("rb") as input_handle:
            total = 0
            while True:
                chunk = input_handle.read(_CHUNK)
                if not chunk:
                    break
                if not header:
                    header = chunk[:16]
                total += len(chunk)
                if total > MAX_MEDIA_BYTES:
                    raise ValueError("媒体文件超过 1 TB 理论上限")
                digest.update(chunk)
        extension = _safe_extension(kind, original_name or source.name, header)
        target = directory / f"{digest.hexdigest()}{extension}"
        if target.exists():
            return ("img:" if kind == "image" else "att:") + target.name
        with temporary.open("wb") as output_handle, source.open("rb") as input_handle:
            _encrypt_stream(input_handle, output_handle)
        os.replace(temporary, target)
        return ("img:" if kind == "image" else "att:") + target.name
    finally:
        temporary.unlink(missing_ok=True)


def import_bytes(value: bytes, kind: str, original_name: str = "") -> str:
    if _active_vault_context() is not None:
        if len(value) > MAX_MEDIA_BYTES:
            raise ValueError("媒体文件超过 1 TB 理论上限")
        return "data:application/octet-stream;base64," + base64.b64encode(value).decode("ascii")
    directory = _kind_dir(kind)
    fd, name = tempfile.mkstemp(prefix="bytes-", suffix=".tmp", dir=directory)
    os.close(fd)
    temporary = Path(name)
    try:
        temporary.write_bytes(value)
        return import_file(temporary, kind, original_name)
    finally:
        temporary.unlink(missing_ok=True)


def _migrate_legacy(path: Path, raw: bytes | None = None) -> None:
    """把旧全局目录里的明文媒体加密迁入当前库目录，随后删除旧文件。

    被引用媒体总能从本库 payload blob 重新物化，因此删除旧明文不丢数据。
    """
    if not path.is_relative_to(_legacy_root()) or not _context_stack:
        return
    kind = "image" if path.parent == _legacy_kind_dir("image") else "attachment"
    target = _kind_dir(kind) / path.name
    if target.exists():
        try:
            path.unlink()
        except OSError:
            pass
        return
    try:
        if raw is not None:
            target.write_bytes(_encrypt(raw))
        else:
            with path.open("rb") as src, target.open("wb") as dst:
                _encrypt_stream(src, dst)
        path.unlink()
    except OSError:
        target.unlink(missing_ok=True)


def iter_decrypted(path: Path, chunk: int = 1024 * 1024):
    """产生媒体文件的解密后明文块；旧明文直接原样产出。

    用于流式处理媒体，避免在磁盘上落明文临时文件。
    """
    with path.open("rb") as input_handle:
        header = input_handle.read(_HEADER_LEN)
        if header.startswith(_MAGIC):
            size = os.fstat(input_handle.fileno()).st_size
            input_handle.seek(size - _TAG_LEN)
            tag = input_handle.read(_TAG_LEN)
            input_handle.seek(_HEADER_LEN)
            nonce = header[_HEADER_LEN - _NONCE_LEN:]
            decryptor = Cipher(algorithms.AES(_media_key()), modes.GCM(nonce, tag)).decryptor()
            decryptor.authenticate_additional_data(_MEDIA_INFO)
            remaining = size - _HEADER_LEN - _TAG_LEN
            while remaining > 0:
                piece = input_handle.read(min(chunk, remaining))
                if not piece:
                    break
                remaining -= len(piece)
                out = decryptor.update(piece)
                if out:
                    yield out
            final = decryptor.finalize()
            if final:
                yield final
        else:
            input_handle.seek(0)
            while True:
                piece = input_handle.read(chunk)
                if not piece:
                    break
                yield piece


def path_plaintext_size(path: Path) -> int:
    """媒体文件的明文字节数（加密文件扣除 MAGIC+nonce+tag 开销）。"""
    size = Path(path).stat().st_size
    if size >= _HEADER_LEN + _TAG_LEN:
        with Path(path).open("rb") as handle:
            if handle.read(len(_MAGIC)) == _MAGIC:
                return size - _HEADER_LEN - _TAG_LEN
    return size


def _staged_path(value: object) -> Path | None:
    if not isinstance(value, str) or value.startswith(("img:", "att:")):
        return None
    candidate = Path(value)
    return candidate if candidate.is_absolute() and candidate.is_file() else None


def read_bytes(value: object, max_bytes: int = 64 * 1024 * 1024) -> bytes:
    object_ref = _object_ref(value)
    if object_ref is not None:
        if object_ref.size > max_bytes:
            raise ValueError("媒体文件过大，无法一次载入")
        output = io.BytesIO()
        _require_vault_context().open_media_object(object_ref, output)
        data = output.getvalue()
        if len(data) != object_ref.size or hashlib.sha256(data).digest() != object_ref.sha256:
            raise ValueError("PMVE 媒体对象完整性不匹配")
        return data
    path = resolve_ref(value)
    staged = _staged_path(value)
    if staged is not None:
        if staged.stat().st_size > max_bytes:
            raise ValueError("媒体文件过大，无法一次载入")
        return staged.read_bytes()
    if path is not None:
        if path_plaintext_size(path) > max_bytes:
            raise ValueError("媒体文件过大，无法一次载入")
        raw = path.read_bytes()
        if raw.startswith(_MAGIC):
            data = _decrypt(raw)
        else:
            data = raw
            _migrate_legacy(path, raw)
        if len(data) > max_bytes:
            raise ValueError("媒体文件过大，无法一次载入")
        return data
    if _is_legacy_ref(value):
        raise FileNotFoundError("附件或图片文件不存在，可能尚未同步或已被清理")
    if not isinstance(value, str):
        raise ValueError("媒体值不是有效引用或 base64 文本")
    raw = _decode_base64(value)
    if len(raw) > max_bytes:
        raise ValueError("媒体文件过大，无法一次载入")
    return raw


def read_range(value: object, offset: int, length: int, max_bytes: int = 64 * 1024 * 1024) -> bytes:
    """Read a bounded PMVE object range without materializing the whole object."""
    object_ref = _object_ref(value)
    if object_ref is None:
        data = read_bytes(value, max_bytes=max_bytes)
        return data[offset : offset + length]
    if type(offset) is not int or type(length) is not int or offset < 0 or length < 0:
        raise ValueError("媒体范围必须是非负整数")
    if offset > object_ref.size or length > object_ref.size - offset:
        raise ValueError("媒体范围超出对象边界")
    if length > max_bytes:
        raise ValueError("媒体范围过大，无法一次载入")
    output = io.BytesIO()
    _require_vault_context().open_media_range(object_ref, offset, length, output)
    data = output.getvalue()
    if len(data) != length:
        raise ValueError("PMVE 媒体对象范围长度不匹配")
    return data


def to_base64(value: object, max_bytes: int = 64 * 1024 * 1024) -> str:
    return base64.b64encode(read_bytes(value, max_bytes)).decode("ascii")


def export_value(value: object, destination: Path) -> None:
    """把引用或内联 base64 的解密内容写入 destination。"""
    destination = Path(destination)
    object_ref = _object_ref(value)
    if object_ref is not None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
        os.close(fd)
        temporary = Path(temporary_name)
        try:
            with temporary.open("wb") as output_handle:
                writer = _VerifyingWriter(output_handle)
                _require_vault_context().open_media_object(object_ref, writer)
                _verify_stream(object_ref, writer)
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
        return
    source = resolve_ref(value)
    staged = _staged_path(value)
    if staged is not None:
        with staged.open("rb") as input_handle, destination.open("wb") as output_handle:
            shutil.copyfileobj(input_handle, output_handle, _CHUNK)
        return
    if source is not None:
        with source.open("rb") as probe:
            is_encrypted = probe.read(len(_MAGIC)) == _MAGIC
        with source.open("rb") as input_handle, destination.open("wb") as output_handle:
            if is_encrypted:
                _decrypt_stream(input_handle, output_handle)
            else:
                shutil.copyfileobj(input_handle, output_handle, _CHUNK)
                _migrate_legacy(source)
        return
    if _is_legacy_ref(value):
        raise FileNotFoundError("附件或图片文件不存在，可能尚未同步或已被清理")
    if not isinstance(value, str):
        raise ValueError("媒体值不是有效引用或 base64 文本")
    clean = value
    if clean.startswith("data:") and ";base64," in clean:
        clean = clean.split(",", 1)[1]
    clean = "".join(clean.split())
    with destination.open("wb") as output_handle:
        for offset in range(0, len(clean), 256 * 1024):
            output_handle.write(_decode_base64(clean[offset : offset + 256 * 1024]))


def value_size(value: object) -> int:
    object_ref = _object_ref(value)
    if object_ref is not None:
        return object_ref.size
    path = resolve_ref(value)
    staged = _staged_path(value)
    if staged is not None:
        return staged.stat().st_size
    if path is not None:
        if path.stat().st_size < _HEADER_LEN + _TAG_LEN:
            return path.stat().st_size
        return path.stat().st_size - _HEADER_LEN - _TAG_LEN
    if not isinstance(value, str):
        raise ValueError("媒体值不是有效引用或 base64 文本")
    if value.startswith("data:") and ";base64," in value:
        value = value.split(",", 1)[1]
    padding = len(value) - len(value.rstrip("="))
    return max(0, len(value) * 3 // 4 - padding)


def value_sha256(value: object) -> str:
    object_ref = _object_ref(value)
    if object_ref is not None:
        return object_ref.sha256.hex()
    path = resolve_ref(value)
    staged = _staged_path(value)
    if staged is not None:
        digest = hashlib.sha256()
        with staged.open("rb") as handle:
            for chunk in iter(lambda: handle.read(_CHUNK), b""):
                digest.update(chunk)
        return digest.hexdigest()
    if path is not None and _is_legacy_ref(value):
        assert isinstance(value, str)
        digest = Path(value.split(":", 1)[1]).stem
        if len(digest) == 64:
            return digest
    return hashlib.sha256(read_bytes(value)).hexdigest()


def cache_key(value: object) -> str:
    object_ref = _object_ref(value)
    if object_ref is not None:
        return object_ref.to_external_string()
    return str(value)[:256]


def has_pending_imports(entry) -> bool:
    return any(
        (occurrence.classification is pmv_media_ref.Classification.INLINE or
         (occurrence.classification is pmv_media_ref.Classification.LEGACY_EXTERNAL
          and _staged_path(occurrence.raw) is not None))
        for occurrence in pmv_media_ref.scan(entry)
    )


def commit_entry_imports(vault, entry, *, expected_entry_updated_at: float | None = None):
    """Atomically import staged UI files and publish their ObjectRefs with the Entry."""
    occurrences = tuple(
        occurrence
        for occurrence in pmv_media_ref.scan(entry)
        if (occurrence.classification is pmv_media_ref.Classification.INLINE or
            (occurrence.classification is pmv_media_ref.Classification.LEGACY_EXTERNAL
             and _staged_path(occurrence.raw) is not None))
    )
    if not occurrences:
        raise ValueError("条目没有待导入的 PMVE 媒体")
    handles = []
    try:
        streams = []
        for occurrence in occurrences:
            path = _staged_path(occurrence.raw)
            assert occurrence.kind is not None
            if path is not None:
                expected_size = path.stat().st_size
                handle = path.open("rb")
            else:
                assert isinstance(occurrence.raw, str)
                raw = _decode_base64(occurrence.raw)
                expected_size = len(raw)
                handle = io.BytesIO(raw)
            handles.append(handle)
            streams.append(pmv_media_ref.LegacyStream(
                occurrence.path,
                handle,
                expected_size,
                uuid.uuid4(),
                1,
                occurrence.kind,
            ))
        transform = pmv_media_ref.plan(entry, tuple(streams))
        refs = vault.import_media_mutation(
            transform,
            expected_sequence=vault.pmve_identity.sequence,
            target_entry=entry,
            expected_entry_updated_at=expected_entry_updated_at,
        )
        transformed = transform.transform(refs)
        for committed in getattr(vault, "entries", ()):
            if committed.id == entry.id:
                return committed
        return transformed
    finally:
        for handle in handles:
            handle.close()
