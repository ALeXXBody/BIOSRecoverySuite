"""UEFI firmware volume / FFS pattern patcher with UEFIPatch-compatible input.

Implements the workflow used by the Lenovo BIOS unlocking community
(UEFIPatch / UEFITool patch format, thinkpad-firmware-patches collections):

  * parses firmware volumes (_FVH), FFS files and section trees
  * follows GUID-defined LZMA compressed sections (decompress / recompress)
  * applies equal-length byte patches scoped by FFS GUID + section type
  * rebuilds file headers/checksums, alignment pad files and FV free space

Patch line format ('#' comments, UEFIPatch style):

    <FFS-GUID> <section-type-hex> P:<find-hex>:<replace-hex> [...]

GUID FFFFFFFF-...-FFFFFFFF with scope 0 means: scan the whole image (global).
Find and replace hex must have equal length (same rule as UEFIPatch).
"""

import json
import lzma
import os
import re
import struct
from dataclasses import dataclass, field
from typing import Optional

FV_SIGNATURE = b"_FVH"
FFS2_GUID = "8C8CE578-8A3D-4F1C-9935-896185C32DD3"
FFS3_GUID = "5473C07A-3DCB-4DCA-BD6F-1E9689E7349A"
LZMA_GUID = "EE4E5898-3914-4259-9D6E-DC7BD79403CF"
LZMAF86_GUID = "D42AE6BD-1352-4BFB-909A-CA72A6EAE889"

SEC_COMPRESSION = 0x01
SEC_GUID_DEFINED = 0x02
SEC_PE32 = 0x10
SEC_FV_IMAGE = 0x17
FFS_PAD_FILE = 0xF0
FFS_ATTRIB_CHECKSUM = 0x40
FFS_ATTRIB_LARGE_FILE = 0x01
FFS_MIN_HEADER = 0x18
ERASE_POLARITY_BIT = 0x00000800
GLOBAL_GUID = "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"


def guid_to_bytes(guid: str) -> bytes:
    p = guid.strip("{}").split("-")
    return (struct.pack("<IHH", int(p[0], 16), int(p[1], 16), int(p[2], 16))
            + bytes.fromhex(p[3]) + bytes.fromhex(p[4]))


def bytes_to_guid(b: bytes) -> str:
    d1, d2, d3 = struct.unpack_from("<IHH", b, 0)
    return f"{d1:08X}-{d2:04X}-{d3:04X}-{b[8:10].hex().upper()}-{b[10:16].hex().upper()}"


def _align(x: int, a: int) -> int:
    return (x + a - 1) & ~(a - 1)


@dataclass
class SectionNode:
    stype: int
    off: int                  # offset of section start within its storage buffer
    hdr_size: int
    body_off: int
    body_size: int
    guid: Optional[str] = None
    comp: Optional[str] = None          # 'lzma' | 'lzmaf86' | 'efi' | 'tiano'
    kind: str = "raw"                   # raw | sections | fv | unknown
    data: Optional[bytearray] = None    # decompressed content; ONLY storage owners own this
    children: list = field(default_factory=list)   # SectionNode or FileNode
    parent_file: Optional["FileNode"] = None


@dataclass(eq=False)
class FileNode:
    guid: str
    off: int                  # offset within its storage buffer (image if storage is None)
    hdr_size: int
    size: int
    ftype: int
    attrs: int
    state: int
    align: int
    sections: list = field(default_factory=list)
    storage: Optional[SectionNode] = None   # owning lzma container; None = image buffer
    dirty: bool = False


class UEFIPatchError(Exception):
    pass


class UEFIPatcher:
    """Applies UEFIPatch-format pattern patches to UEFI firmware images."""

    def __init__(self, patches_path: Optional[str] = None):
        self.patches_path = patches_path or self._default_patches_path()
        self.groups: list[dict] = []
        self._load_patches()

    def _default_patches_path(self) -> str:
        here = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(os.path.dirname(os.path.dirname(here)), "patches", "lenovo_patches.txt")

    # ------------------------------------------------------------------ #
    #  patch registry                                                    #
    # ------------------------------------------------------------------ #

    def _load_patches(self):
        self.groups = []
        if not os.path.exists(self.patches_path):
            return
        cur = None
        with open(self.patches_path, "r") as f:
            for raw in f:
                line = raw.strip()
                if not line:
                    continue
                m = re.match(r"#\s*@(\w+)\s+(.*)", line)
                if m:
                    key, val = m.group(1), m.group(2).strip()
                    if key == "group":
                        cur = {"key": val, "desc": "", "models": "", "source": "",
                               "lines": []}
                        self.groups.append(cur)
                    elif cur is not None and key in ("desc", "models", "source"):
                        cur[key] = val
                    continue
                if line.startswith("#") or cur is None:
                    continue
                parsed = self._parse_line(line)
                if parsed:
                    cur["lines"].append(parsed)

    def _parse_line(self, line: str):
        parts = line.split()
        if len(parts) < 3:
            return None
        try:
            guid = parts[0]
            guid_to_bytes(guid)  # validate shape
            scope = int(parts[1], 16)
            ops = []
            for op in parts[2:]:
                if op.startswith("P:"):
                    find, repl = op[2:].split(":", 1)
                    fb, rb = bytes.fromhex(find), bytes.fromhex(repl)
                    if len(fb) != len(rb) or not fb:
                        return None
                    ops.append((fb, rb))
            return (guid, scope, ops) if ops else None
        except (ValueError, IndexError):
            return None

    # ------------------------------------------------------------------ #
    #  image parsing                                                     #
    # ------------------------------------------------------------------ #

    def find_fvs(self, data) -> list[tuple[int, int, int, int]]:
        """(offset, length, header_length, attributes) of every FFS FV in buffer."""
        out = []
        idx = 0
        while True:
            idx = data.find(FV_SIGNATURE, idx)
            if idx < 0:
                break
            fv_start = idx - 0x28
            if fv_start >= 0 and fv_start + 0x48 <= len(data):
                fs_guid = bytes_to_guid(data[fv_start + 0x10:fv_start + 0x20])
                if fs_guid in (FFS2_GUID, FFS3_GUID):
                    fv_len = struct.unpack_from("<Q", data, fv_start + 0x20)[0]
                    hdr_len = struct.unpack_from("<H", data, fv_start + 0x30)[0]
                    attrs = struct.unpack_from("<I", data, fv_start + 0x2C)[0]
                    if 0 < fv_len <= len(data) - fv_start and hdr_len >= 0x48:
                        out.append((fv_start, fv_len, hdr_len, attrs))
            idx += 4
        return out

    def parse_fv_files(self, buf, fv_off: int, fv_len: int, hdr_len: int,
                       attrs: int, storage: Optional[SectionNode]) -> list[FileNode]:
        polarity = bool(attrs & ERASE_POLARITY_BIT)
        files = []
        off = fv_off + hdr_len
        end = fv_off + fv_len
        resync_tries = 0
        while off + FFS_MIN_HEADER <= end:
            hdr = buf[off:off + FFS_MIN_HEADER]
            free = (all(b == 0x00 for b in hdr)) if polarity else (all(b == 0xFF for b in hdr))
            if free:
                break
            state = hdr[0x17]
            eff = (~state & 0xFF) if polarity else state
            attrs_f = hdr[0x13]
            size = hdr[0x14] | (hdr[0x15] << 8) | (hdr[0x16] << 16)
            hdr_size = FFS_MIN_HEADER
            if (attrs_f & FFS_ATTRIB_LARGE_FILE) and size == 0xFFFFFF:
                size = struct.unpack_from("<Q", buf, off + 0x18)[0]
                hdr_size = 0x20
            valid = (eff & 0x06) == 0x06 and size >= hdr_size and off + size <= end
            if not valid:
                # step over pad-file bodies / unknown gaps and try to resync
                resync_tries += 1
                if resync_tries > 64:
                    break
                off += 8
                continue
            resync_tries = 0
            node = FileNode(
                guid=bytes_to_guid(hdr[0:16]),
                off=off, hdr_size=hdr_size, size=size,
                ftype=hdr[0x12], attrs=attrs_f, state=state,
                align=max(8, 1 << ((attrs_f >> 3) & 0x07)),
                storage=storage,
            )
            node.sections = self.parse_sections(buf, off + hdr_size, node, storage)
            files.append(node)
            off = _align(off + size, 8)
        return files

    def parse_sections(self, buf, base: int, parent_file: FileNode,
                       storage: Optional[SectionNode]) -> list:
        """Parse a section chain inside `buf`; base = chain offset within buf."""
        out = []
        off = base
        end = len(buf)
        while off + 4 <= end:
            size = buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16)
            stype = buf[off + 3]
            hdr = 4
            if size == 0xFFFFFF:
                if off + 8 > end:
                    break
                size = struct.unpack_from("<I", buf, off + 4)[0]
                hdr = 8
            if size < hdr or off + size > end:
                break
            body_off = off + hdr
            node = SectionNode(stype=stype, off=off, hdr_size=hdr,
                               body_off=body_off, body_size=size - hdr,
                               parent_file=parent_file)

            if stype == SEC_GUID_DEFINED and body_off + 20 <= off + size:
                node.guid = bytes_to_guid(buf[body_off:body_off + 16])
                data_off = struct.unpack_from("<H", buf, body_off + 16)[0]
                payload = bytes(buf[off + data_off:off + size])
                if node.guid == LZMA_GUID:
                    node.comp = "lzma"
                    try:
                        node.data = bytearray(lzma.decompress(payload, format=lzma.FORMAT_ALONE))
                    except lzma.LZMAError:
                        node.kind = "unknown"
                    else:
                        child_storage = node
                        kids = self.parse_sections(node.data, 0, parent_file, child_storage)
                        if kids:
                            node.kind = "sections"
                            node.children = kids
                        else:
                            fv_files = self.parse_fv_files(node.data, 0, len(node.data),
                                                           0x48, 0, child_storage)
                            if fv_files:
                                node.kind = "fv"
                                node.children = fv_files
                            else:
                                node.kind = "unknown"
                elif node.guid == LZMAF86_GUID:
                    node.comp = "lzmaf86"
                    node.kind = "unknown"
                else:
                    node.kind = "unknown"
            elif stype == SEC_COMPRESSION and body_off + 5 <= off + size:
                ctype = buf[body_off + 4]
                if ctype == 0:
                    node.kind = "sections"
                    # uncompressed payload stays inside the same buffer
                    node.children = self.parse_sections(buf, body_off + 5, parent_file, storage)
                else:
                    node.comp = {1: "efi", 2: "tiano"}.get(ctype, "unknown")
                    node.kind = "unknown"
            elif stype == SEC_FV_IMAGE:
                node.kind = "fv"
                node.children = self.parse_fv_files(buf, body_off, size - hdr,
                                                    0x48, 0, storage)
            out.append(node)
            off = _align(off + size, 4)
        return out

    def iter_files(self, buf):
        """All FFS files reachable from `buf`, including inside containers."""
        seen = set()

        def emit(files):
            for f in files:
                key = (id(f.storage), f.off) if f.storage is not None else (None, f.off)
                if key not in seen:
                    seen.add(key)
                    yield f

        def walk_sections(sections):
            for n in sections:
                if isinstance(n, SectionNode):
                    if n.kind == "fv":
                        yield from emit(n.children)
                    yield from walk_sections(n.children)

        for fv_off, fv_len, hdr_len, attrs in self.find_fvs(buf):
            top = self.parse_fv_files(buf, fv_off, fv_len, hdr_len, attrs, None)
            yield from emit(top)
            for f in top:
                yield from walk_sections(f.sections)

    def _walk_nodes(self, nodes):
        for n in nodes:
            yield n
            if isinstance(n, SectionNode):
                yield from self._walk_nodes(n.children)

    def _walk_nodes_scoped(self, nodes, buf, owner=None):
        """Yield (node, buffer, owner) where buffer is the byte buffer the
        node's offsets refer to and owner is the SectionNode owning that
        buffer (None = outer image/file buffer)."""
        for n in nodes:
            yield n, buf, owner
            if isinstance(n, SectionNode):
                if n.data is not None and n.kind in ("sections", "fv"):
                    child_buf, child_owner = n.data, n
                else:
                    child_buf, child_owner = buf, owner
                yield from self._walk_nodes_scoped(n.children, child_buf, child_owner)

    # ------------------------------------------------------------------ #
    #  patching                                                          #
    # ------------------------------------------------------------------ #

    def _buffer_for(self, fnode: FileNode, image: bytearray):
        return fnode.storage.data if fnode.storage is not None else image

    def _region_for_scope(self, image: bytearray, guid: str, scope: int):
        """Yield (buffer, offset, length, file, storage_owner) patch targets.

        storage_owner is the SectionNode owning the buffer (None = image/file)."""
        if guid == GLOBAL_GUID and scope == 0:
            yield (image, 0, len(image), None, None)
            return
        for f in self.iter_files(image):
            if f.guid != guid:
                continue
            base_buf = self._buffer_for(f, image)
            base_owner = f.storage
            if scope == 0:
                yield (base_buf, f.off + f.hdr_size, f.size - f.hdr_size, f, base_owner)
                continue
            found = False
            for node, buf, owner in self._walk_nodes_scoped(f.sections, base_buf, base_owner):
                if isinstance(node, SectionNode) and node.stype == scope:
                    yield (buf, node.body_off, node.body_size, f, owner)
                    found = True
            if not found:
                yield (base_buf, f.off + f.hdr_size, f.size - f.hdr_size, f, base_owner)

    def scan(self, image_path: str) -> dict:
        """Dry-run: matches per patch group."""
        with open(image_path, "rb") as f:
            image = bytearray(f.read())
        result = {}
        for g in self.groups:
            total = 0
            per_line = []
            for guid, scope, ops in g["lines"]:
                count = 0
                for buf, off, length, _f, _owner in self._region_for_scope(image, guid, scope):
                    region = bytes(buf[off:off + length])
                    for fb, _rb in ops:
                        idx = region.find(fb)
                        while idx >= 0:
                            count += 1
                            idx = region.find(fb, idx + 1)
                per_line.append(count)
                total += count
            result[g["key"]] = {"matches": total, "per_line": per_line,
                                "desc": g["desc"], "models": g["models"]}
        return result

    def apply(self, input_path: str, output_path: str,
              group_keys: Optional[list] = None) -> dict:
        with open(input_path, "rb") as f:
            image = bytearray(f.read())

        wanted = set(group_keys) if group_keys else {g["key"] for g in self.groups}
        dirty_storages = {}          # id(buffer) -> owner SectionNode
        dirty_files = set()
        report = {"applied": [], "messages": [], "success": True}

        for g in self.groups:
            if g["key"] not in wanted:
                continue
            hits = 0
            for guid, scope, ops in g["lines"]:
                for buf, off, length, fnode, owner in self._region_for_scope(image, guid, scope):
                    for fb, rb in ops:
                        idx = 0
                        while True:
                            idx = bytes(buf[off:off + length]).find(fb, idx)
                            if idx < 0:
                                break
                            pos = off + idx
                            buf[pos:pos + len(fb)] = rb
                            hits += 1
                            idx += len(rb)
                            if owner is not None:
                                dirty_storages[id(owner.data)] = owner
                            if fnode is not None:
                                fnode.dirty = True
                                dirty_files.add(fnode)
            if hits:
                report["applied"].append({"group": g["key"], "patches": hits})
            else:
                report["messages"].append(
                    f"group '{g['key']}': no patterns matched (image unchanged by this group)")

        # file-level checksum refresh (equal-length patches only)
        for fnode in dirty_files:
            self._refresh_file_checksums(image, fnode)

        # re-encode dirty LZMA containers and splice their files back
        for fnode in list(dirty_files):
            if fnode.storage is not None:
                raise UEFIPatchError(
                    "patched file lives inside a compressed container; "
                    "single-level LZMA patching is supported")
            spliced = False
            for sec in fnode.sections:
                if id(sec.data) in dirty_storages:
                    self._recompress_into_image(image, sec, fnode)
                    spliced = True
                else:
                    for deep in self._walk_nodes(sec.children):
                        if isinstance(deep, SectionNode) and id(deep.data) in dirty_storages:
                            raise UEFIPatchError(
                                "patched content lives in a nested compressed container; "
                                "single-level LZMA patching is supported")
            if spliced:
                dirty_files.discard(fnode)

        with open(output_path, "wb") as f:
            f.write(bytes(image))
        report["output_path"] = output_path
        report["matches_total"] = sum(a["patches"] for a in report["applied"])
        return report

    # ------------------------------------------------------------------ #
    #  rebuild helpers                                                   #
    # ------------------------------------------------------------------ #

    def _refresh_file_checksums(self, image: bytearray, fnode: FileNode):
        buf = self._buffer_for(fnode, image)
        off = fnode.off
        hdr = bytearray(buf[off:off + fnode.hdr_size])
        if len(hdr) < fnode.hdr_size:
            return
        probe = bytearray(hdr)
        probe[0x10] = 0
        probe[0x11] = 0
        probe[0x17] = 0
        hdr[0x10] = (0x100 - (sum(probe) & 0xFF)) & 0xFF
        if fnode.attrs & FFS_ATTRIB_CHECKSUM:
            body = buf[off + fnode.hdr_size: off + fnode.size]
            hdr[0x11] = (0x100 - (sum(body) & 0xFF)) & 0xFF
        else:
            hdr[0x11] = 0xAA
        buf[off:off + fnode.hdr_size] = hdr

    def _lzma_section_bytes(self, node: SectionNode) -> bytes:
        payload = lzma.compress(bytes(node.data), format=lzma.FORMAT_ALONE,
                                filters=[{"id": lzma.FILTER_LZMA1, "preset": 9,
                                          "dict_size": 1 << 24}])
        hdr_len = 4
        total = hdr_len + 20 + len(payload)
        if total <= 0xFFFFFF:
            hdr = struct.pack("<I", total)[:3] + bytes([SEC_GUID_DEFINED])
            doff = hdr_len + 20
        else:
            hdr_len = 8
            total = hdr_len + 20 + len(payload)
            hdr = b"\xFF\xFF\xFF" + bytes([SEC_GUID_DEFINED]) + struct.pack("<I", total)
            doff = hdr_len + 20
        body = guid_to_bytes(LZMA_GUID) + struct.pack("<HH", doff, 0x01) + payload
        return hdr + body

    def _recompress_into_image(self, image: bytearray, node: SectionNode, fnode: FileNode):
        new_section = self._lzma_section_bytes(node)

        new_body = b""
        for sec in fnode.sections:          # top-level sections only
            if sec is node:
                raw = new_section
            else:
                raw = bytes(image[sec.off:sec.off + sec.hdr_size + sec.body_size])
            new_body += raw
            new_body += b"\xFF" * (_align(len(raw), 4) - len(raw))
        new_size = fnode.hdr_size + len(new_body)

        hdr = bytearray(image[fnode.off:fnode.off + fnode.hdr_size])
        state = hdr[0x17]
        size3 = new_size if new_size <= 0xFFFFFF else 0xFFFFFF
        hdr[0x14] = size3 & 0xFF
        hdr[0x15] = (size3 >> 8) & 0xFF
        hdr[0x16] = (size3 >> 16) & 0xFF
        probe = bytearray(hdr)
        probe[0x10] = 0
        probe[0x11] = 0
        probe[0x17] = 0
        hdr[0x10] = (0x100 - (sum(probe) & 0xFF)) & 0xFF
        if fnode.attrs & FFS_ATTRIB_CHECKSUM:
            hdr[0x11] = (0x100 - (sum(new_body) & 0xFF)) & 0xFF
        else:
            hdr[0x11] = 0xAA
        if new_size > 0xFFFFFF and fnode.hdr_size >= 0x20:
            struct.pack_into("<Q", hdr, 0x18, new_size)
        new_file = bytes(hdr) + new_body
        self._splice_file_in_fv(image, fnode, new_file, state)

    def _splice_file_in_fv(self, image: bytearray, fnode: FileNode,
                           new_file: bytes, state: Optional[int] = None):
        """Replace fnode's bytes with new_file inside its FV, shifting
        subsequent files (with alignment pad files) and restoring free space."""
        if state is None:
            state = image[fnode.off + 0x17]
        fv = None
        for fv_off, fv_len, hdr_len, attrs in self.find_fvs(image):
            if fv_off + hdr_len <= fnode.off < fv_off + fv_len:
                fv = (fv_off, fv_len, hdr_len)
                break
        if fv is None:
            raise UEFIPatchError("file's firmware volume not found")
        fv_off, fv_len, hdr_len = fv

        siblings = sorted(
            (f for f in self.iter_files(image)
             if f.storage is None and fv_off + hdr_len <= f.off < fv_off + fv_len),
            key=lambda f: f.off)

        tail = []
        past = False
        for s in siblings:
            if s.off == fnode.off:
                tail.append((new_file, s.align, state))
                past = True
            elif past:
                tail.append((bytes(image[s.off:s.off + s.size]), s.align, s.state))

        pos = fnode.off
        blob = bytearray()
        for raw, align, fstate in tail:
            target = _align(pos, align)
            if target > pos:
                blob += self._make_pad_file(pos, target, fstate)
                pos = target
            blob += raw
            pos += len(raw)
        end = fv_off + fv_len
        blob += b"\xFF" * (end - (fnode.off + len(blob)))
        image[fnode.off:end] = blob

    def _make_pad_file(self, pos: int, target: int, state: int) -> bytes:
        size = target - pos
        if size < 0x18:
            size = _align(pos + 0x18, 8) - pos
        hdr = bytearray(0x18)
        hdr[0:16] = b"\xFF" * 16
        hdr[0x12] = FFS_PAD_FILE
        hdr[0x14] = size & 0xFF
        hdr[0x15] = (size >> 8) & 0xFF
        hdr[0x16] = (size >> 16) & 0xFF
        hdr[0x17] = state
        probe = bytearray(hdr)
        probe[0x10] = 0
        probe[0x11] = 0
        probe[0x17] = 0
        hdr[0x10] = (0x100 - (sum(probe) & 0xFF)) & 0xFF
        hdr[0x11] = 0xAA
        return bytes(hdr) + b"\xFF" * (size - 0x18)

    # ------------------------------------------------------------------ #
    #  DXE driver replacement (Lenovo autopatch mechanism)               #
    # ------------------------------------------------------------------ #

    def _default_dxe_registry_path(self) -> str:
        here = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(os.path.dirname(os.path.dirname(here)), "patches", "dxe_replacements.json")

    def load_dxe_replacements(self, registry_path: Optional[str] = None) -> list[dict]:
        path = registry_path or self._default_dxe_registry_path()
        if not os.path.exists(path):
            return []
        try:
            with open(path, "r") as f:
                raw = json.load(f)
        except (OSError, json.JSONDecodeError):
            return []
        items = raw if isinstance(raw, list) else raw.get("replacements", [])
        out = []
        for it in items:
            out.append({
                "key": it.get("key", ""),
                "file": it.get("file", ""),
                "target_guid": it.get("target_guid", ""),
                "description": it.get("description", ""),
                "verified": bool(it.get("verified", False)),
                "source": it.get("source", ""),
            })
        return out

    def save_dxe_replacements(self, entries: list[dict], registry_path: Optional[str] = None):
        path = registry_path or self._default_dxe_registry_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump({"replacements": entries}, f, indent=2)

    @staticmethod
    def _looks_like_ffs(blob: bytes, guid: str) -> bool:
        if len(blob) < 0x18:
            return False
        try:
            return bytes_to_guid(blob[:16]) == guid
        except Exception:
            return False

    def build_replacement_file(self, target: FileNode, driver_bytes: bytes) -> bytes:
        """Wrap or adopt driver_bytes as a complete FFS file replacing target."""
        state = target.state
        attrs = target.attrs & ~FFS_ATTRIB_LARGE_FILE

        if self._looks_like_ffs(driver_bytes, target.guid):
            size3 = driver_bytes[0x14] | (driver_bytes[0x15] << 8) | (driver_bytes[0x16] << 16)
            if 0x18 <= size3 <= len(driver_bytes) and size3 != 0xFFFFFF:
                blob = bytearray(driver_bytes[:0x18])
                body = driver_bytes[0x18:size3]
            else:
                body = struct.pack("<I", 4 + len(driver_bytes))[:3] + bytes([0x19]) + driver_bytes
                size = 0x18 + len(body)
                blob = bytearray(0x18)
                blob[0:16] = guid_to_bytes(target.guid)
                blob[0x12] = target.ftype
                blob[0x14] = size & 0xFF
                blob[0x15] = (size >> 8) & 0xFF
                blob[0x16] = (size >> 16) & 0xFF
        else:
            if driver_bytes[:2] == b"MZ":
                body = struct.pack("<I", 4 + len(driver_bytes))[:3] + bytes([SEC_PE32]) + driver_bytes
            else:
                # unknown payload: keep it verbatim in a RAW section
                body = struct.pack("<I", 4 + len(driver_bytes))[:3] + bytes([0x19]) + driver_bytes
            size = 0x18 + len(body)
            blob = bytearray(0x18)
            blob[0:16] = guid_to_bytes(target.guid)
            blob[0x12] = target.ftype
            blob[0x14] = size & 0xFF
            blob[0x15] = (size >> 8) & 0xFF
            blob[0x16] = (size >> 16) & 0xFF

        blob[0x13] = attrs
        blob[0x17] = state
        probe = bytearray(blob[:0x18])
        probe[0x10] = 0
        probe[0x11] = 0
        probe[0x17] = 0
        blob[0x10] = (0x100 - (sum(probe) & 0xFF)) & 0xFF
        if attrs & FFS_ATTRIB_CHECKSUM:
            blob[0x11] = (0x100 - (sum(body) & 0xFF)) & 0xFF
        else:
            blob[0x11] = 0xAA
        return bytes(blob[:0x18]) + bytes(body)

    def replace_ffs_file(self, image_path: str, output_path: str,
                         target_guid: str, driver_path: str) -> dict:
        """Replace the FFS file with target_guid by the provided driver binary."""
        with open(image_path, "rb") as f:
            image = bytearray(f.read())
        with open(driver_path, "rb") as f:
            driver_bytes = f.read()

        target = None
        for f in self.iter_files(image):
            if f.guid == target_guid:
                target = f
                break
        if target is None:
            return {"success": False, "message": f"no FFS file with GUID {target_guid} found"}
        if target.storage is not None:
            return {"success": False,
                    "message": "target file lives inside a compressed container; not supported yet"}

        new_file = self.build_replacement_file(target, driver_bytes)
        self._splice_file_in_fv(image, target, new_file)

        with open(output_path, "wb") as f:
            f.write(bytes(image))
        return {"success": True, "message": f"replaced FFS file {target_guid}",
                "output_path": output_path,
                "old_size": target.size, "new_size": len(new_file)}

    def list_files(self, image_path: str) -> list[dict]:
        """Enumerate FFS files with driver names (from UI sections) for user guidance."""
        with open(image_path, "rb") as f:
            image = bytearray(f.read())
        out = []
        for fnode in self.iter_files(image):
            name = None
            for node in self._walk_nodes(fnode.sections):
                if isinstance(node, SectionNode) and node.stype == 0x16:
                    buf = fnode.storage.data if fnode.storage is not None else image
                    body = bytes(buf[node.body_off:node.body_off + node.body_size])
                    try:
                        name = body.decode("utf-16-le", errors="replace").rstrip("\x00")
                    except Exception:
                        name = None
                    break
            out.append({"guid": fnode.guid, "type": fnode.ftype, "size": fnode.size,
                        "offset": fnode.off, "name": name})
        return out

    def derive_replacements(self, original_path: str, patched_path: str,
                            out_dir: str) -> list[dict]:
        """Diff an original and a patched (e.g. badcaps-autopatched) dump and
        extract every replaced FFS file as a reusable replacement entry."""
        os.makedirs(out_dir, exist_ok=True)
        with open(original_path, "rb") as f:
            orig = f.read()
        with open(patched_path, "rb") as f:
            patched = f.read()

        orig_files = {f.guid: f for f in self.iter_files(bytearray(orig))}
        patched_files = {f.guid: f for f in self.iter_files(bytearray(patched))}

        derived = []
        for guid, pnode in patched_files.items():
            onode = orig_files.get(guid)
            if onode is None:
                continue
            if bytes(orig[onode.off:onode.off + onode.size]) == \
                    bytes(patched[pnode.off:pnode.off + pnode.size]):
                continue
            fname = f"{guid}.ffs"
            with open(os.path.join(out_dir, fname), "wb") as f:
                f.write(bytes(patched[pnode.off:pnode.off + pnode.size]))
            derived.append({
                "key": f"derived_{guid.lower()[:8]}",
                "file": fname,
                "target_guid": guid,
                "description": f"auto-derived replacement for {guid} "
                               f"({'.'.join(str(seg) for seg in [pnode.ftype])})",
                "verified": False,
                "source": f"diffed pair {os.path.basename(original_path)} -> "
                          f"{os.path.basename(patched_path)}",
            })
        return derived

    # ------------------------------------------------------------------ #
    #  NVRAM clean pass (autopatch step 2)                               #
    # ------------------------------------------------------------------ #

    def replace_nvram_volume(self, image_path: str, output_path: str,
                             vol_path: str) -> dict:
        """Replace a firmware volume in-place with the supplied clean image.

        Faithful to the reference autopatcher: a target FV matches when its
        first 48 bytes (ZeroVector + FileSystemGuid + FvLength) are identical,
        AND its total size and header checksum equal the replacement's. The
        volume is then overwritten in place (sizes must match)."""
        with open(image_path, "rb") as f:
            image = bytearray(f.read())
        with open(vol_path, "rb") as f:
            vol = f.read()
        if len(vol) < 0x48:
            return {"success": False, "message": "volume image too small"}

        pattern = vol[:48]
        vol_size = int.from_bytes(vol[0x20:0x23], "little")   # FvLength, low 3 bytes
        vol_checksum = int.from_bytes(vol[0x32:0x34], "little")

        def _finish(res):
            with open(output_path, "wb") as f:
                f.write(bytes(image))
            return res

        pos = image.find(pattern)
        if pos < 0:
            return _finish({"success": False,
                            "message": "no matching firmware volume found in image (NVRAM layout differs)",
                            "skipped": True})
        # FvLength low 3 bytes live at FV header offset 0x20..0x22 (little)
        tgt_size = int.from_bytes(image[pos + 0x20:pos + 0x23], "little")
        tgt_checksum = int.from_bytes(image[pos + 0x32:pos + 0x34], "little")
        if tgt_size != vol_size:
            return _finish({"success": False, "skipped": True,
                            "message": f"volume size mismatch (image {tgt_size} vs replacement {vol_size}) - skipped"})
        if tgt_checksum != vol_checksum:
            return _finish({"success": False, "skipped": True,
                            "message": f"volume header checksum mismatch (image 0x{tgt_checksum:x} vs "
                                       f"replacement 0x{vol_checksum:x}) - skipped"})
        image[pos:pos + len(vol)] = vol
        return _finish({"success": True, "message": f"NVRAM volume replaced at 0x{pos:X}",
                        "output_path": output_path, "offset": pos})

    def run_autopatch(self, image_path: str, output_path: str,
                      include_nvram: bool = True) -> dict:
        """Full badcaps-style flow: DXE driver replacement, then NVRAM clean."""
        import shutil
        shutil.copyfile(image_path, output_path)
        report = {"steps": [], "success": True}
        patches_dir = os.path.dirname(self.patches_path)

        for entry in self.load_dxe_replacements():
            bin_path = os.path.join(patches_dir, "dxe", entry["file"])
            if not os.path.exists(bin_path):
                report["steps"].append({"step": entry["key"], "ok": False,
                                        "message": f"binary missing: {entry['file']}"})
                continue
            nxt = output_path + ".tmp"
            res = self.replace_ffs_file(output_path, nxt, entry["target_guid"], bin_path)
            if res["success"]:
                shutil.move(nxt, output_path)
                report["steps"].append({"step": entry["key"], "ok": True,
                                        "message": res["message"]})
            else:
                report["steps"].append({"step": entry["key"], "ok": False,
                                        "message": res["message"],
                                        "skipped": res.get("skipped", False)})

        if include_nvram:
            vol_path = os.path.join(patches_dir, "dxe", "NVRAM_EfiSystemNvDataFvGuid.vol")
            if os.path.exists(vol_path):
                nxt = output_path + ".tmp"
                res = self.replace_nvram_volume(output_path, nxt, vol_path)
                if res["success"]:
                    shutil.move(nxt, output_path)
                report["steps"].append({"step": "nvram_clean", "ok": res["success"],
                                        "message": res["message"],
                                        "skipped": res.get("skipped", False)})

        report["output_path"] = output_path
        report["success"] = any(s["ok"] for s in report["steps"])
        return report

    # ------------------------------------------------------------------ #
    #  Lenovo-specific detection helpers                                 #
    # ------------------------------------------------------------------ #

    CE_BACKDOOR_GUID = "6ACCE65D-DA35-4B39-B64B-5ED927A7DC7E"
    KNOWN_DRIVERS = [
        "LenovoWmaPolicyDxe", "SystemFormBrowserCoreDxe", "SvpPasswdDxe",
        "LenovoSvpPasswordDxe", "ThinkPadPasswordDxe", "H2OFormBrowserDxe",
        "SetupUtilityApp", "LenovoSetupConfigurationDxe",
    ]
    TAMPER_MARKER = bytes.fromhex("4C4E564242534543FB")   # LNVBBSEC + FB
    TAMPER_PATCHED = bytes.fromhex("4C4E564242534543FF")  # LNVBBSEC + FF

    def detect_lenovo(self, image_path: str) -> dict:
        """Detect Lenovo unlock-relevant features in an image."""
        with open(image_path, "rb") as f:
            data = f.read()
        out = {
            "is_lenovo": False,
            "ce_backdoor": {"guid_hits": [], "string_hits": []},
            "tamper_marker": None,
            "tamper_already_patched": False,
            "drivers": [],
        }
        gbytes = guid_to_bytes(self.CE_BACKDOOR_GUID)
        idx = data.find(gbytes)
        while idx >= 0:
            out["ce_backdoor"]["guid_hits"].append(idx)
            idx = data.find(gbytes, idx + 1)
        needle = "cE!".encode("utf-16-le")
        idx = data.find(needle)
        while idx >= 0:
            out["ce_backdoor"]["string_hits"].append(idx)
            idx = data.find(needle, idx + 1)
        if self.TAMPER_MARKER in data:
            out["tamper_marker"] = data.find(self.TAMPER_MARKER)
        if self.TAMPER_PATCHED in data:
            out["tamper_already_patched"] = True
        for drv in self.KNOWN_DRIVERS:
            ascii_hits = data.count(drv.encode("ascii"))
            utf16_hits = data.count(drv.encode("utf-16-le"))
            if ascii_hits or utf16_hits:
                out["drivers"].append({"name": drv, "ascii_hits": ascii_hits,
                                       "utf16_hits": utf16_hits})
        out["is_lenovo"] = bool(out["drivers"]) or bool(out["ce_backdoor"]["guid_hits"]) \
            or out["tamper_marker"] is not None
        return out
