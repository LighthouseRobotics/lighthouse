#!/usr/bin/env python3
"""Write the shared conformance corpus for lighthouse-bundle/v1.

Usage: python3 corpus.py OUT_DIR

Writes one .zip per case and expected.json mapping each file name to "OK" or
the rejection code both verifiers must return. The Python and JS test suites
read the same corpus, so the two verifiers cannot drift apart silently.
"""

import hashlib
import io
import json
import os
import stat
import struct
import sys
import warnings
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import lighthouse_bundle as lb  # noqa: E402

CREATED = "2026-10-14T12:00:00Z"
warnings.filterwarnings("ignore", "Duplicate name")
FILE_MODE = (stat.S_IFREG | 0o644) << 16


def sha(data):
    return hashlib.sha256(data).hexdigest()


def manifest_for(files, **overrides):
    manifest = {
        "schema": lb.SCHEMA,
        "producer": {"app": "corpus", "version": "1"},
        "created": CREATED,
        "payloadSchema": "corpus.payload.v1",
        "reality": "synthetic",
        "files": [{"path": p, "bytes": len(d), "sha256": sha(d)} for p, d in sorted(files.items())],
        "omissions": [],
        "boundary": "Synthetic conformance case.",
    }
    manifest.update(overrides)
    return manifest


def encode(manifest):
    return (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")


def build(members, method=zipfile.ZIP_DEFLATED, comment=b"", modes=None, force_zip64=()):
    """members: list of (name, bytes). Returns ZIP bytes."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.comment = comment
        for name, data in members:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = method
            info.create_system = 3
            info.external_attr = (modes or {}).get(name, FILE_MODE if not name.endswith("/") else
                                                   (stat.S_IFDIR | 0o755) << 16)
            info.file_size = len(data)
            with archive.open(info, "w", force_zip64=name in force_zip64) as handle:
                handle.write(data)
    return buffer.getvalue()


def bundle(files, extra_members=(), manifest=None, raw_manifest=None, **kwargs):
    body = raw_manifest if raw_manifest is not None else encode(manifest or manifest_for(files))
    members = [(lb.MANIFEST, body)] + sorted(files.items()) + list(extra_members)
    return build(members, **kwargs)


def patch_flags(data, name, set_bits=0, clear_bits=0):
    """Change general-purpose flag bits in both the local and central header of ``name``."""
    out = bytearray(data)
    raw = name.encode("utf-8")
    for signature, flag_at, name_len_at, name_at in ((b"PK\x03\x04", 6, 26, 30), (b"PK\x01\x02", 8, 28, 46)):
        start = 0
        while True:
            pos = out.find(signature, start)
            if pos < 0:
                break
            length = struct.unpack_from("<H", out, pos + name_len_at)[0]
            if bytes(out[pos + name_at:pos + name_at + length]) == raw:
                flags = struct.unpack_from("<H", out, pos + flag_at)[0]
                struct.pack_into("<H", out, pos + flag_at, (flags | set_bits) & ~clear_bits)
            start = pos + 4
    return bytes(out)


def patch_local_name(data, old, new):
    """Rename only the local header copy of a member (same length)."""
    assert len(old) == len(new)
    out = bytearray(data)
    pos = out.find(b"PK\x03\x04" + b"")
    while pos >= 0:
        length = struct.unpack_from("<H", out, pos + 26)[0]
        if bytes(out[pos + 30:pos + 30 + length]) == old.encode():
            out[pos + 30:pos + 30 + length] = new.encode()
            return bytes(out)
        pos = out.find(b"PK\x03\x04", pos + 4)
    raise ValueError("member not found")


def patch_member_field(data, name, local_at, central_at, fmt, value):
    """Overwrite a fixed header field of ``name`` in its local and central headers."""
    out = bytearray(data)
    raw = name.encode("utf-8")
    for signature, at, name_len_at, name_at in ((b"PK\x03\x04", local_at, 26, 30), (b"PK\x01\x02", central_at, 28, 46)):
        if at is None:
            continue
        pos = out.find(signature)
        while pos >= 0:
            length = struct.unpack_from("<H", out, pos + name_len_at)[0]
            if bytes(out[pos + name_at:pos + name_at + length]) == raw:
                struct.pack_into(fmt, out, pos + at, value)
            pos = out.find(signature, pos + 4)
    return bytes(out)


def replace_name_bytes(data, old, new):
    assert len(old) == len(new)
    return data.replace(old, new)


class _Unseekable(io.RawIOBase):
    def __init__(self):
        self.buffer = io.BytesIO()

    def writable(self):
        return True

    def write(self, b):
        return self.buffer.write(b)


def build_streamed(members):
    """Write through a non-seekable stream so zipfile uses data descriptors (flag bit 3)."""
    sink = _Unseekable()
    with zipfile.ZipFile(sink, "w") as archive:
        for name, data in members:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = FILE_MODE
            with archive.open(info, "w") as handle:
                handle.write(data)
    return sink.buffer.getvalue()


def cases():
    a = {"payload/a.txt": b"alpha\n", "payload/data/b.json": b'{"b": 2}\n'}
    one = {"payload/a.txt": b"alpha\n"}
    yield "ok_basic", "OK", bundle(a)
    yield "ok_stored", "OK", bundle(a, method=zipfile.ZIP_STORED)
    yield "ok_comment", "OK", bundle(a, comment=b"archive comment")
    yield "bad_comment_lookalike", "E_ZIP", bundle(a, comment=b"comment PK\x05\x06 lookalike")
    yield "ok_zip64_member", "OK", bundle(one, force_zip64=("payload/a.txt",))
    yield "ok_directory_entries", "OK", bundle(a, extra_members=[("payload/", b""), ("payload/data/", b"")])
    yield "ok_unicode_name", "OK", bundle({"payload/café.txt": b"latte\n"})
    yield "ok_empty_file", "OK", bundle({"payload/empty": b""})
    yield "ok_extension_key", "OK", bundle(one, manifest=manifest_for(one, **{"x-note": "extension"}))
    yield "ok_source_and_omission", "OK", bundle(one, manifest=manifest_for(
        one, source={"id": "item-1", "description": "test"},
        omissions=[{"what": "originals", "why": "too large"}]))
    big = os.urandom(64 * 1024)
    yield "ok_binary_64k", "OK", bundle({"payload/random.bin": big})

    yield "ok_data_descriptor", "OK", build_streamed([(lb.MANIFEST, encode(manifest_for(a)))] + sorted(a.items()))
    yield "bad_nul_in_name", "E_PATH", replace_name_bytes(
        bundle(one, extra_members=[("payload/aXq.txt", b"x")]), b"payload/aXq.txt", b"payload/a\x00q.txt")
    yield "bad_crc_only", "E_HASH", patch_member_field(bundle(one, method=zipfile.ZIP_STORED), "payload/a.txt",
                                                       14, 16, "<L", 0x12345678)
    yield "bad_patched_data_flag", "E_MEMBER", patch_flags(bundle(a), "payload/a.txt", set_bits=0x20)
    yield "bad_overlap_size", "E_ZIP", patch_member_field(bundle(a), "payload/a.txt",
                                                          None, 20, "<L", 4000)
    floaty = manifest_for(one)
    yield "bad_manifest_bytes_float", "E_MANIFEST", bundle(
        one, raw_manifest=encode(floaty).replace(b'"bytes": 6', b'"bytes": 6.0'))
    yield "bad_manifest_bom", "E_MANIFEST", bundle(one, raw_manifest=b"\xef\xbb\xbf" + encode(manifest_for(one)))
    yield "bad_manifest_bool_bytes", "E_MANIFEST", bundle(
        one, raw_manifest=encode(floaty).replace(b'"bytes": 6', b'"bytes": true'))
    bad = manifest_for(a)
    bad["files"][0]["sha256"] = "0" * 64
    yield "bad_hash", "E_HASH", bundle(a, manifest=bad)
    bad = manifest_for(a)
    bad["files"][0]["bytes"] += 1
    yield "bad_bytes", "E_HASH", bundle(a, manifest=bad)
    yield "bad_unlisted_member", "E_LIST", bundle(one, extra_members=[("payload/sneaky.txt", b"x")])
    yield "bad_missing_member", "E_LIST", build([(lb.MANIFEST, encode(manifest_for(a))),
                                                 ("payload/a.txt", a["payload/a.txt"])])
    yield "bad_traversal", "E_PATH", bundle(one, extra_members=[("payload/../evil.txt", b"x")])
    yield "bad_absolute", "E_PATH", bundle(one, extra_members=[("/payload/abs.txt", b"x")])
    yield "bad_backslash", "E_PATH", bundle(one, extra_members=[("payload\\win.txt", b"x")])
    yield "bad_outside_payload", "E_PATH", bundle(one, extra_members=[("other/x.txt", b"x")])
    yield "bad_case_collision", "E_PATH", bundle({"payload/A.txt": b"1", "payload/a.txt": b"2"})
    yield "bad_not_nfc", "E_PATH", bundle(one, extra_members=[("payload/café.txt", b"x")])
    yield "bad_reserved_name", "E_PATH", bundle(one, extra_members=[("payload/CON.txt", b"x")])
    yield "bad_trailing_dot", "E_PATH", bundle(one, extra_members=[("payload/name.", b"x")])
    yield "bad_control_char", "E_PATH", bundle(one, extra_members=[("payload/a\x01b", b"x")])
    yield "bad_duplicate_member", "E_PATH", bundle(one, extra_members=[("payload/a.txt", b"other")])
    yield "bad_non_utf8_flag", "E_PATH", patch_flags(
        bundle({"payload/café.txt": b"latte\n"}), "payload/café.txt", clear_bits=0x800)
    yield "bad_symlink", "E_MEMBER", bundle(one, extra_members=[("payload/link", b"/etc/passwd")],
                                            modes={"payload/link": (stat.S_IFLNK | 0o777) << 16})
    yield "bad_encrypted_flag", "E_MEMBER", patch_flags(bundle(a), "payload/a.txt", set_bits=0x1)
    yield "bad_method_bzip2", "E_MEMBER", bundle(one, method=zipfile.ZIP_BZIP2)
    yield "bad_directory_with_content", "E_MEMBER", bundle(one, extra_members=[("payload/d/", b"data")])
    zeros = {"payload/zeros.bin": bytes(3 << 20)}
    yield "bad_compression_ratio", "E_LIMIT", bundle(zeros)
    good = bundle(a)
    yield "bad_prepended_data", "E_ZIP", b"MZjunk" + good
    yield "bad_trailing_data", "E_ZIP", good + b"trailing"
    yield "bad_truncated", "E_ZIP", good[:-10]
    yield "bad_not_a_zip", "E_ZIP", b"this is not a zip file at all" * 3
    yield "bad_local_name_mismatch", "E_ZIP", patch_local_name(bundle(a), "payload/a.txt", "payload/z.txt")
    corrupt = bytearray(bundle(one, method=zipfile.ZIP_STORED))
    at = corrupt.find(b"alpha\n")
    corrupt[at] ^= 0xFF
    yield "bad_corrupt_stored_data", "E_HASH", bytes(corrupt)
    yield "bad_manifest_missing", "E_MANIFEST", build(sorted(one.items()))
    yield "bad_manifest_duplicate_key", "E_MANIFEST", bundle(
        one, raw_manifest=encode(manifest_for(one))[:-2] + b',\n  "schema": "lighthouse-bundle/v1"\n}\n')
    yield "bad_manifest_nan", "E_MANIFEST", bundle(
        one, raw_manifest=encode(manifest_for(one)).replace(b'"version": "1"', b'"version": NaN'))
    yield "bad_manifest_unknown_key", "E_MANIFEST", bundle(one, manifest=manifest_for(one, claims=["all good"]))
    yield "bad_manifest_schema", "E_MANIFEST", bundle(one, manifest=manifest_for(one, schema="lighthouse-bundle/v2"))
    yield "bad_manifest_reality", "E_MANIFEST", bundle(one, manifest=manifest_for(one, reality="probably-real"))
    unsorted = manifest_for(a)
    unsorted["files"].reverse()
    yield "bad_manifest_unsorted", "E_MANIFEST", bundle(a, manifest=unsorted)
    yield "bad_manifest_not_utf8", "E_MANIFEST", bundle(one, raw_manifest=b"\xff\xfe{}")
    yield "bad_manifest_created", "E_MANIFEST", bundle(one, manifest=manifest_for(one, created="2026-10-14 12:00"))
    yield "bad_manifest_empty_files", "E_MANIFEST", build([(lb.MANIFEST, encode(manifest_for({})))])


def main(out):
    os.makedirs(out, exist_ok=True)
    expected = {}
    for name, code, data in cases():
        path = os.path.join(out, name + ".zip")
        with open(path, "wb") as handle:
            handle.write(data)
        expected[name + ".zip"] = code
    with open(os.path.join(out, "expected.json"), "w") as handle:
        json.dump(expected, handle, indent=2, sort_keys=True)
    return expected


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    print(json.dumps(main(sys.argv[1]), indent=2, sort_keys=True))
