"""SQL holds only a content reference; response JSON stays on this host."""
import hashlib
import json
from pathlib import Path
import re
import zlib

from farm.local_files import atomic_bytes

ROOT = Path(__file__).resolve().parents[1] / '.private/responses'
MAGIC = b'KLF1:'


def save_response(response, root=None):
    raw = json.dumps(response, ensure_ascii=False, separators=(',', ':')).encode()
    sha = hashlib.sha256(raw).hexdigest()
    folder = Path(root) if root is not None else ROOT
    path = folder / sha[:2] / (sha + '.json.z')
    # Always atomically replace: repair an incomplete/corrupt previous file.
    atomic_bytes(path, zlib.compress(raw))
    return MAGIC + sha.encode(), sha


def load_response(reference, root=None):
    reference = bytes(reference)
    if not reference.startswith(MAGIC):
        # Read historical records without re-uploading them on new writes.
        return json.loads(zlib.decompress(reference))
    sha = reference[len(MAGIC):].decode('ascii')
    if not re.fullmatch('[0-9a-f]{64}', sha):
        raise ValueError('invalid_local_response_reference')
    folder = Path(root) if root is not None else ROOT
    path = folder / sha[:2] / (sha + '.json.z')
    if path.is_symlink() or path.resolve().parent.parent != folder.resolve():
        raise ValueError('invalid_local_response_path')
    raw = zlib.decompress(path.read_bytes())
    if hashlib.sha256(raw).hexdigest() != sha:
        raise ValueError('local_response_hash_mismatch')
    return json.loads(raw)


def local_reference(reference):
    """Subset runs reuse local references; old DB blobs are localized once."""
    reference = bytes(reference)
    if reference.startswith(MAGIC):
        load_response(reference)
        return reference
    return save_response(load_response(reference))[0]
