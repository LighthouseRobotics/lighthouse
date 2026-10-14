#!/usr/bin/env python3
"""Create and verify lighthouse-bundle/v1 archives.

A bundle is an ordinary ZIP file holding one envelope manifest,
``lighthouse-bundle.json``, plus the producing app's own export, unchanged,
under ``payload/``. The verifier checks the archive structure before Python's
zipfile reads the central directory, then checks every listed file's byte count
and SHA-256. It never extracts or executes anything.

Standard library only. See SPEC.md beside this file.
"""

import argparse
import datetime
import hashlib
import io
import json
import os
import re
import stat
import struct
import sys
import tempfile
import unicodedata
import zipfile
import zlib

SCHEMA = "lighthouse-bundle/v1"
REPORT_SCHEMA = "lighthouse-bundle-verification/v1"
MANIFEST = "lighthouse-bundle.json"
PAYLOAD = "payload/"
REALITY = ("physical", "simulated", "synthetic", "unknown")
LIMITS = {
    "archive_bytes": 1 << 30,          # 1 GiB on disk
    "total_uncompressed": 2 << 30,     # 2 GiB of declared member bytes
    "entries": 20000,
    "directory_bytes": 8 << 20,        # central directory
    "manifest_bytes": 16 << 20,
    "ratio": 200,                      # max uncompressed/compressed for members over 1 MiB
    "path_bytes": 512,
}
VERIFIER_BOUNDARY = ("Verified that every listed file is present with the recorded byte count and SHA-256, "
                     "and that the archive holds nothing else. Sender authenticity, completeness beyond the "
                     "listed files and the truth of the payload's own claims are not established.")

_HEX64 = re.compile(r"[0-9a-f]{64}")
_APP = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
_COMMIT = re.compile(r"[0-9a-f]{7,64}")
_CREATED = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z")
_RESERVED = re.compile(r"(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?", re.IGNORECASE)
_TOP_KEYS = {"schema", "producer", "created", "payloadSchema", "reality", "files", "omissions", "boundary", "source"}
_REQUIRED = {"schema", "producer", "created", "payloadSchema", "reality", "files", "omissions", "boundary"}


class BundleError(ValueError):
    """A rejected bundle. ``code`` is stable across the Python and JS verifiers."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------- paths

def check_path(name, limits=LIMITS):
    """Raise E_PATH unless ``name`` is a portable, relative, normalized member path."""
    if not isinstance(name, str) or not name:
        raise BundleError("E_PATH", "Empty member path.")
    if len(name.encode("utf-8")) > limits["path_bytes"]:
        raise BundleError("E_PATH", "Member path is too long: " + name[:80])
    if unicodedata.normalize("NFC", name) != name:
        raise BundleError("E_PATH", "Member path is not NFC-normalized: " + name)
    if "\\" in name or ":" in name or name.startswith("/"):
        raise BundleError("E_PATH", "Absolute or non-portable member path: " + name)
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in name):
        raise BundleError("E_PATH", "Control character in member path.")
    body = name[:-1] if name.endswith("/") else name
    for segment in body.split("/"):
        if segment in ("", ".", ".."):
            raise BundleError("E_PATH", "Empty, '.' or '..' segment in member path: " + name)
        if segment != segment.rstrip(" .") or _RESERVED.fullmatch(segment):
            raise BundleError("E_PATH", "Segment not portable to Windows: " + name)
    if name != MANIFEST and not name.startswith(PAYLOAD):
        raise BundleError("E_PATH", "Member outside payload/: " + name)
    return name


def collision_key(name):
    return unicodedata.normalize("NFC", name).lower()


# ---------------------------------------------------------------- strict JSON

def strict_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise BundleError("E_MANIFEST", "Duplicate JSON key: " + key)
            result[key] = value
        return result

    def nonfinite(value):
        raise BundleError("E_MANIFEST", "Non-finite JSON number: " + value)

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise BundleError("E_MANIFEST", "Manifest is not UTF-8.") from None
    try:
        return json.loads(text, object_pairs_hook=unique, parse_constant=nonfinite)
    except BundleError:
        raise
    except ValueError as error:
        raise BundleError("E_MANIFEST", "Manifest is not valid JSON: " + str(error)) from None


def _string(value, limit, field):
    if not isinstance(value, str) or not value or len(value) > limit:
        raise BundleError("E_MANIFEST", f"{field} must be a non-empty string of at most {limit} characters.")
    return value


def check_manifest(manifest, limits=LIMITS):
    """Validate the envelope. Returns the list of listed files."""
    if not isinstance(manifest, dict):
        raise BundleError("E_MANIFEST", "Manifest must be a JSON object.")
    unknown = [k for k in manifest if k not in _TOP_KEYS and not k.startswith("x-")]
    if unknown:
        raise BundleError("E_MANIFEST", "Unknown manifest keys: " + ", ".join(sorted(unknown)))
    missing = _REQUIRED - set(manifest)
    if missing:
        raise BundleError("E_MANIFEST", "Missing manifest keys: " + ", ".join(sorted(missing)))
    if manifest["schema"] != SCHEMA:
        raise BundleError("E_MANIFEST", "Unsupported schema: " + repr(manifest["schema"]))
    producer = manifest["producer"]
    if not isinstance(producer, dict) or set(producer) - {"app", "version", "repository", "commit"}:
        raise BundleError("E_MANIFEST", "producer must hold only app, version, repository and commit.")
    if not isinstance(producer.get("app"), str) or not _APP.fullmatch(producer["app"]):
        raise BundleError("E_MANIFEST", "producer.app must be a lowercase slug.")
    _string(producer.get("version"), 100, "producer.version")
    if "repository" in producer:
        _string(producer["repository"], 200, "producer.repository")
    if "commit" in producer and (not isinstance(producer["commit"], str) or not _COMMIT.fullmatch(producer["commit"])):
        raise BundleError("E_MANIFEST", "producer.commit must be 7-64 lowercase hex characters.")
    if not isinstance(manifest["created"], str) or not _CREATED.fullmatch(manifest["created"]):
        raise BundleError("E_MANIFEST", "created must be an RFC 3339 UTC time ending in Z.")
    _string(manifest["payloadSchema"], 200, "payloadSchema")
    if manifest["reality"] not in REALITY:
        raise BundleError("E_MANIFEST", "reality must be one of " + ", ".join(REALITY) + ".")
    _string(manifest["boundary"], 4000, "boundary")
    omissions = manifest["omissions"]
    if not isinstance(omissions, list) or len(omissions) > 1000:
        raise BundleError("E_MANIFEST", "omissions must be a list of at most 1000 entries.")
    for item in omissions:
        if not isinstance(item, dict) or set(item) != {"what", "why"}:
            raise BundleError("E_MANIFEST", "Each omission needs exactly 'what' and 'why'.")
        _string(item["what"], 500, "omission.what")
        _string(item["why"], 2000, "omission.why")
    if "source" in manifest:
        source = manifest["source"]
        if not isinstance(source, dict) or set(source) - {"id", "description"} or "id" not in source:
            raise BundleError("E_MANIFEST", "source must hold id and optional description.")
        _string(source["id"], 500, "source.id")
        if "description" in source:
            _string(source["description"], 2000, "source.description")
    files = manifest["files"]
    if not isinstance(files, list) or not files or len(files) > limits["entries"]:
        raise BundleError("E_MANIFEST", "files must be a non-empty list within the entry limit.")
    previous = None
    for entry in files:
        if not isinstance(entry, dict) or set(entry) - {"path", "bytes", "sha256", "mediaType"} or \
                not {"path", "bytes", "sha256"} <= set(entry):
            raise BundleError("E_MANIFEST", "Each file needs path, bytes, sha256 and optional mediaType.")
        path = entry["path"]
        if not isinstance(path, str) or not path.startswith(PAYLOAD) or path.endswith("/"):
            raise BundleError("E_MANIFEST", "Listed file paths must be files under payload/.")
        try:
            check_path(path, limits)
        except BundleError as error:
            raise BundleError("E_MANIFEST", "Listed path is unsafe: " + str(error)) from None
        if type(entry["bytes"]) is not int or entry["bytes"] < 0:
            raise BundleError("E_MANIFEST", "bytes must be a non-negative integer: " + path)
        if not isinstance(entry["sha256"], str) or not _HEX64.fullmatch(entry["sha256"]):
            raise BundleError("E_MANIFEST", "sha256 must be 64 lowercase hex characters: " + path)
        if "mediaType" in entry:
            _string(entry["mediaType"], 200, "mediaType")
        if previous is not None and path <= previous:
            raise BundleError("E_MANIFEST", "files must be sorted by path with no duplicates.")
        previous = path
    return files


# ---------------------------------------------------------------- ZIP structure

def directory_bounds(stream, size, limits=LIMITS):
    """Locate and bound the central directory before zipfile allocates its index.

    Returns (entry count, directory offset). Rejects multipart archives, data before the first
    member and an inconsistent directory location.
    """
    if size < 22:
        raise BundleError("E_ZIP", "Missing ZIP end record.")
    tail_len = min(size, 22 + 0xFFFF)
    stream.seek(size - tail_len)
    tail = stream.read(tail_len)
    pos = tail.rfind(b"PK\x05\x06")
    record = None
    while pos >= 0:
        if pos + 22 <= len(tail):
            fields = struct.unpack("<4s4H2LH", tail[pos:pos + 22])
            if pos + 22 + fields[7] == len(tail):
                record = fields
                break
        pos = tail.rfind(b"PK\x05\x06", 0, pos)
    if record is None:
        raise BundleError("E_ZIP", "Missing ZIP end record.")
    _, disk, cd_disk, on_disk, total, cd_size, cd_offset, _comment = record
    eocd = size - tail_len + pos
    if b"PK\x05\x06" in tail[pos + 22:]:
        raise BundleError("E_ZIP", "Archive comment contains an end-record signature (ambiguous archive).")
    if disk or cd_disk or on_disk != total:
        raise BundleError("E_ZIP", "Multipart ZIP archives are not supported.")
    directory_end = eocd
    if total == 0xFFFF or cd_size == 0xFFFFFFFF or cd_offset == 0xFFFFFFFF:
        if eocd < 20:
            raise BundleError("E_ZIP", "Missing ZIP64 locator.")
        stream.seek(eocd - 20)
        sig, z_disk, z_offset, z_disks = struct.unpack("<4sLQL", stream.read(20))
        if sig != b"PK\x06\x07" or z_disk or z_disks != 1 or z_offset + 56 > eocd - 20:
            raise BundleError("E_ZIP", "Invalid ZIP64 locator.")
        stream.seek(z_offset)
        fields = struct.unpack("<4sQ2H2L4Q", stream.read(56))
        if fields[0] != b"PK\x06\x06" or fields[4] or fields[5] or fields[6] != fields[7]:
            raise BundleError("E_ZIP", "Invalid or multipart ZIP64 end record.")
        total, cd_size, cd_offset = fields[7], fields[8], fields[9]
        directory_end = z_offset
    if total > limits["entries"]:
        raise BundleError("E_LIMIT", f"Archive has {total} entries; the limit is {limits['entries']}.")
    if cd_size > limits["directory_bytes"]:
        raise BundleError("E_LIMIT", "Central directory exceeds its size limit.")
    if cd_offset + cd_size != directory_end:
        raise BundleError("E_ZIP", "Central directory location is inconsistent (prepended or trailing data).")
    if total == 0:
        raise BundleError("E_ZIP", "Archive is empty.")
    if total:
        stream.seek(0)
        if stream.read(4) != b"PK\x03\x04":
            raise BundleError("E_ZIP", "Archive does not start with a member (prepended data).")
    return total, cd_offset


def _read_bounded(archive, info, limit):
    with archive.open(info) as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise BundleError("E_LIMIT", "Member exceeds its size limit: " + info.filename)
    return data


def _check_member(info, limits):
    name = info.filename
    if info.orig_filename != name:
        raise BundleError("E_PATH", "NUL or separator rewrite in member name.")
    raw_ascii = all(ord(ch) < 128 for ch in name)
    if not raw_ascii and not info.flag_bits & 0x800:
        raise BundleError("E_PATH", "Non-ASCII member name without the UTF-8 flag.")
    check_path(name, limits)
    if info.flag_bits & 0x2061:
        raise BundleError("E_MEMBER", "Encrypted or patched member: " + name)
    if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        raise BundleError("E_MEMBER", "Unsupported compression method: " + name)
    mode = stat.S_IFMT(info.external_attr >> 16)
    if name.endswith("/"):
        if info.file_size or mode not in (0, stat.S_IFDIR):
            raise BundleError("E_MEMBER", "Directory entry with content or wrong type: " + name)
        return False
    if mode not in (0, stat.S_IFREG):
        raise BundleError("E_MEMBER", "Non-regular member (symlink or device): " + name)
    if info.compress_type == zipfile.ZIP_STORED and info.compress_size != info.file_size:
        raise BundleError("E_MEMBER", "Stored member with mismatched sizes: " + name)
    if info.file_size > (1 << 20) and info.file_size > info.compress_size * limits["ratio"]:
        raise BundleError("E_LIMIT", "Compression ratio exceeds the limit: " + name)
    return True


def _check_layout(stream, infos, directory_offset):
    """Every local header must match its directory entry, and member data must
    not overlap another member or the central directory (overlap bombs)."""
    spans = []
    for info in infos:
        stream.seek(info.header_offset)
        header = stream.read(30)
        if len(header) != 30 or header[:4] != b"PK\x03\x04":
            raise BundleError("E_ZIP", "Missing local header: " + info.filename)
        name_len, extra_len = struct.unpack("<HH", header[26:30])
        raw = stream.read(name_len)
        expected = info.orig_filename.encode("utf-8" if info.flag_bits & 0x800 else "cp437")
        if raw != expected:
            raise BundleError("E_ZIP", "Local header name differs from the directory: " + info.filename)
        start = info.header_offset
        end = start + 30 + name_len + extra_len + info.compress_size
        spans.append((start, end, info.filename))
    spans.sort()
    for index, (start, end, name) in enumerate(spans):
        limit = spans[index + 1][0] if index + 1 < len(spans) else directory_offset
        if end > limit:
            raise BundleError("E_ZIP", "Member data overlaps the next member or the directory: " + name)


def verify(source, expected_sha256=None, limits=None):
    """Verify a bundle from a path or a seekable binary stream.

    Returns a report dict. Raises BundleError (with ``code``) on rejection.
    """
    limits = dict(LIMITS, **(limits or {}))
    owned = isinstance(source, (str, os.PathLike))
    stream = open(source, "rb") if owned else source
    try:
        stream.seek(0, 2)
        size = stream.tell()
        if size > limits["archive_bytes"]:
            raise BundleError("E_SIZE", "Archive exceeds its size limit.")
        count, directory_offset = directory_bounds(stream, size, limits)
        stream.seek(0)
        digest = hashlib.sha256()
        while True:
            chunk = stream.read(1 << 20)
            if not chunk:
                break
            digest.update(chunk)
        bundle_sha256 = digest.hexdigest()
        if expected_sha256 is not None and expected_sha256 != bundle_sha256:
            raise BundleError("E_CHECKSUM", "Bundle SHA-256 differs from the expected value.")
        stream.seek(0)
        try:
            archive = zipfile.ZipFile(stream)
        except (zipfile.BadZipFile, OSError, ValueError, struct.error) as error:
            raise BundleError("E_ZIP", "Unreadable ZIP: " + str(error)) from None
        with archive:
            infos = archive.infolist()
            if len(infos) != count:
                raise BundleError("E_ZIP", "Central directory count differs from its end record.")
            seen, keys, members = set(), set(), {}
            total = 0
            for info in infos:
                if info.filename in seen:
                    raise BundleError("E_PATH", "Duplicate member: " + info.filename)
                seen.add(info.filename)
                key = collision_key(info.filename)
                if key in keys:
                    raise BundleError("E_PATH", "Members differ only by case or normalization: " + info.filename)
                keys.add(key)
                if _check_member(info, limits):
                    members[info.filename] = info
                    total += info.file_size
            _check_layout(stream, infos, directory_offset)
            if total > limits["total_uncompressed"]:
                raise BundleError("E_LIMIT", "Declared uncompressed size exceeds the limit.")
            if MANIFEST not in members:
                raise BundleError("E_MANIFEST", "Missing " + MANIFEST + ".")
            try:
                manifest = strict_json(_read_bounded(archive, members[MANIFEST], limits["manifest_bytes"]))
                files = check_manifest(manifest, limits)
            except (zipfile.BadZipFile, zlib.error) as error:
                raise BundleError("E_ZIP", "Corrupt manifest member: " + str(error)) from None
            listed = {entry["path"] for entry in files}
            present = set(members) - {MANIFEST}
            if listed != present:
                extra = sorted(present - listed)[:5]
                absent = sorted(listed - present)[:5]
                raise BundleError("E_LIST", f"Listed and present files differ. Unlisted: {extra}; missing: {absent}.")
            payload_bytes = 0
            for entry in files:
                info = members[entry["path"]]
                if info.file_size != entry["bytes"]:
                    raise BundleError("E_HASH", "Byte count differs: " + entry["path"])
                file_digest = hashlib.sha256()
                seen_bytes = 0
                try:
                    with archive.open(info) as handle:
                        while True:
                            chunk = handle.read(1 << 20)
                            if not chunk:
                                break
                            seen_bytes += len(chunk)
                            if seen_bytes > entry["bytes"]:
                                raise BundleError("E_HASH", "Member is longer than recorded: " + entry["path"])
                            file_digest.update(chunk)
                except (zipfile.BadZipFile, zlib.error, EOFError, NotImplementedError) as error:
                    raise BundleError("E_HASH", f"Member failed its integrity check: {entry['path']} ({error})") from None
                if seen_bytes != entry["bytes"] or file_digest.hexdigest() != entry["sha256"]:
                    raise BundleError("E_HASH", "SHA-256 or byte count differs: " + entry["path"])
                payload_bytes += seen_bytes
        return {
            "schema": REPORT_SCHEMA,
            "status": "verified",
            "bundleSha256": bundle_sha256,
            "producer": manifest["producer"],
            "payloadSchema": manifest["payloadSchema"],
            "reality": manifest["reality"],
            "created": manifest["created"],
            "files": len(files),
            "payloadBytes": payload_bytes,
            "omissions": manifest["omissions"],
            "producerBoundary": manifest["boundary"],
            "boundary": VERIFIER_BOUNDARY,
        }
    finally:
        if owned:
            stream.close()


# ---------------------------------------------------------------- creation

def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def collect(inputs):
    """Map filesystem inputs to payload paths. A directory contributes its tree;
    a file contributes its basename. Symlinks are refused."""
    mapping = {}
    for item in inputs:
        item = os.path.abspath(item)
        if os.path.islink(item):
            raise BundleError("E_PATH", "Refusing symlink input: " + item)
        if os.path.isdir(item):
            for root, dirs, names in os.walk(item):
                dirs.sort()
                for name in sorted(names):
                    full = os.path.join(root, name)
                    if os.path.islink(full):
                        raise BundleError("E_PATH", "Refusing symlink input: " + full)
                    rel = os.path.relpath(full, item).replace(os.sep, "/")
                    mapping[PAYLOAD + unicodedata.normalize("NFC", rel)] = full
                for d in list(dirs):
                    if os.path.islink(os.path.join(root, d)):
                        raise BundleError("E_PATH", "Refusing symlinked directory: " + os.path.join(root, d))
        elif os.path.isfile(item):
            mapping[PAYLOAD + unicodedata.normalize("NFC", os.path.basename(item))] = item
        else:
            raise BundleError("E_PATH", "Input does not exist: " + item)
    return dict(sorted(mapping.items()))


def create(out_path, inputs, app, version, payload_schema, reality="unknown", boundary=None,
           omissions=(), source=None, repository=None, commit=None, created=None,
           compress=True, overwrite=False, limits=None):
    """Write a bundle. Deterministic for identical inputs and ``created``."""
    limits = dict(LIMITS, **(limits or {}))
    if os.path.exists(out_path) and not overwrite:
        raise FileExistsError(out_path)
    mapping = collect(inputs) if not isinstance(inputs, dict) else dict(sorted(inputs.items()))
    if not mapping:
        raise BundleError("E_MANIFEST", "Nothing to bundle.")
    keys = set()
    files = []
    total = 0
    for path, full in mapping.items():
        check_path(path, limits)
        key = collision_key(path)
        if key in keys:
            raise BundleError("E_PATH", "Inputs collide by case or normalization: " + path)
        keys.add(key)
        digest = hashlib.sha256()
        size = 0
        with open(full, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
                size += len(chunk)
        total += size
        files.append({"path": path, "bytes": size, "sha256": digest.hexdigest()})
    if len(files) + 1 > limits["entries"] or total > limits["total_uncompressed"]:
        raise BundleError("E_LIMIT", "Inputs exceed the bundle limits.")
    producer = {"app": app, "version": version}
    if repository:
        producer["repository"] = repository
    if commit:
        producer["commit"] = commit
    manifest = {
        "schema": SCHEMA,
        "producer": producer,
        "created": created or _now(),
        "payloadSchema": payload_schema,
        "reality": reality,
        "files": files,
        "omissions": [dict(o) for o in omissions],
        "boundary": boundary or "The producer made no claims beyond the listed files.",
    }
    if source:
        manifest["source"] = dict(source)
    check_manifest(manifest, limits)
    encoded = (json.dumps(manifest, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    directory = os.path.dirname(os.path.abspath(out_path))
    fd, temp = tempfile.mkstemp(prefix=".bundle-", suffix=".zip", dir=directory)
    os.close(fd)
    method = zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED
    try:
        with zipfile.ZipFile(temp, "w") as archive:
            def info_for(name, size):
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = method
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                info.create_system = 3
                info.file_size = size
                return info
            archive.writestr(info_for(MANIFEST, len(encoded)), encoded)
            for entry in files:
                info = info_for(entry["path"], entry["bytes"])
                with open(mapping[entry["path"]], "rb") as src, archive.open(info, "w") as dst:
                    for chunk in iter(lambda: src.read(1 << 20), b""):
                        dst.write(chunk)
        verify(temp, limits=limits)
        if not overwrite and os.path.exists(out_path):
            raise FileExistsError(out_path)
        os.replace(temp, out_path)
    except BaseException:
        if os.path.exists(temp):
            os.unlink(temp)
        raise
    return manifest


# ---------------------------------------------------------------- CLI

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    v = sub.add_parser("verify", help="Verify a bundle and print a JSON report.")
    v.add_argument("bundle")
    v.add_argument("--sha256", help="Expected SHA-256 of the whole bundle file.")
    c = sub.add_parser("create", help="Wrap files or directories into a bundle.")
    c.add_argument("--out", required=True)
    c.add_argument("--app", required=True)
    c.add_argument("--version", required=True)
    c.add_argument("--payload-schema", required=True)
    c.add_argument("--reality", choices=REALITY, default="unknown")
    c.add_argument("--boundary")
    c.add_argument("--omission", action="append", default=[], metavar="WHAT=WHY")
    c.add_argument("--source-id")
    c.add_argument("--source-description")
    c.add_argument("--repository")
    c.add_argument("--commit")
    c.add_argument("--created", help="Fixed creation time (RFC 3339, Z) for reproducible output.")
    c.add_argument("--store", action="store_true", help="Store members without compression.")
    c.add_argument("--force", action="store_true", help="Replace an existing output file.")
    c.add_argument("inputs", nargs="+")
    args = parser.parse_args(argv)
    try:
        if args.command == "verify":
            report = verify(args.bundle, expected_sha256=args.sha256)
            print(json.dumps(report, indent=2, ensure_ascii=False))
            return 0
        omissions = []
        for item in args.omission:
            what, sep, why = item.partition("=")
            if not sep:
                parser.error("--omission needs WHAT=WHY")
            omissions.append({"what": what, "why": why})
        source = None
        if args.source_id:
            source = {"id": args.source_id}
            if args.source_description:
                source["description"] = args.source_description
        create(args.out, args.inputs, args.app, args.version, args.payload_schema, args.reality,
               args.boundary, omissions, source, args.repository, args.commit, args.created,
               compress=not args.store, overwrite=args.force)
        print(json.dumps(verify(args.out), indent=2, ensure_ascii=False))
        return 0
    except BundleError as error:
        print(json.dumps({"schema": REPORT_SCHEMA, "status": "rejected", "code": error.code,
                          "message": str(error)}, indent=2, ensure_ascii=False))
        return 1
    except FileExistsError as error:
        print("Refusing to overwrite " + str(error) + " (use --force).", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
