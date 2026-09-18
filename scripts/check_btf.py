#!/usr/bin/env python3
"""Validate in-kernel BTF DATASEC entries without bpftool.

Parses the raw .BTF section extracted from vmlinux and mirrors the relevant
part of the kernel's btf_datasec_check_meta(): entries must be non-empty,
in-bounds, and strictly monotonic.
"""
import json, os, shutil, struct, subprocess, sys, tempfile
from pathlib import Path

KIND_NAMES = {
    0: "UNKN", 1: "INT", 2: "PTR", 3: "ARRAY", 4: "STRUCT", 5: "UNION",
    6: "ENUM", 7: "FWD", 8: "TYPEDEF", 9: "VOLATILE", 10: "CONST",
    11: "RESTRICT", 12: "FUNC", 13: "FUNC_PROTO", 14: "VAR", 15: "DATASEC",
    16: "FLOAT", 17: "DECL_TAG", 18: "TYPE_TAG", 19: "ENUM64",
}

def extract_btf(vmlinux: Path) -> bytes:
    objcopy = os.environ.get("OBJCOPY") or shutil.which("llvm-objcopy") or shutil.which("objcopy")
    if not objcopy:
        raise SystemExit("llvm-objcopy/objcopy not found")
    with tempfile.NamedTemporaryFile(prefix="check-btf-", suffix=".bin", delete=False) as tf:
        out = tf.name
    try:
        subprocess.run([objcopy, "--dump-section", f".BTF={out}", str(vmlinux)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        return Path(out).read_bytes()
    finally:
        Path(out).unlink(missing_ok=True)

def parse(data: bytes):
    if len(data) < 24:
        raise SystemExit("BTF too short")
    magic, version, flags, hdr_len, type_off, type_len, str_off, str_len = \
        struct.unpack_from("<HBBIIIII", data, 0)
    if magic != 0xeb9f:
        raise SystemExit(f"bad BTF magic 0x{magic:04x}")
    strings = data[hdr_len + str_off:hdr_len + str_off + str_len]
    def s(off):
        end = strings.find(b"\0", off)
        return strings[off:end].decode(errors="replace") if end >= 0 else ""
    pos = hdr_len + type_off
    end = pos + type_len
    tid = 1
    types = {}
    datasecs = []
    while pos < end:
        if pos + 12 > end:
            raise SystemExit(f"truncated type header at {pos}")
        name_off, info, size_type = struct.unpack_from("<III", data, pos)
        kind = (info >> 24) & 0x1F
        vlen = info & 0xFFFF
        kflag = (info >> 31) & 1
        pos += 12
        extra = 0
        if kind == 1:  # INT
            extra = 4
        elif kind == 3:  # ARRAY
            extra = 12
        elif kind in (4, 5):  # STRUCT / UNION
            extra = 12 * vlen
        elif kind == 6:  # ENUM
            extra = 8 * vlen
        elif kind == 13:  # FUNC_PROTO
            extra = 8 * vlen
        elif kind == 14:  # VAR
            extra = 4
        elif kind == 15:  # DATASEC
            datasecs.append((tid, size_type, vlen, pos))
            extra = 12 * vlen
        elif kind == 17:  # DECL_TAG
            extra = 4
        elif kind == 19:  # ENUM64
            extra = 12 * vlen
        elif kind in (0, 2, 7, 8, 9, 10, 11, 12, 16, 18):
            extra = 0
        else:
            raise SystemExit(f"unknown BTF kind {kind} at type {tid}")
        if pos + extra > end:
            raise SystemExit(f"type {tid} ({KIND_NAMES.get(kind, kind)}) exceeds BTF section")
        types[tid] = {"kind": kind, "name": s(name_off), "size": size_type,
                      "vlen": vlen, "kflag": kflag}
        pos += extra
        tid += 1
    return types, datasecs, data

def validate(vmlinux: Path):
    data = extract_btf(vmlinux)
    types, datasecs, blob = parse(data)
    errors = []
    variables = 0
    for tid, sec_size, vlen, pos in datasecs:
        name = types[tid]["name"]
        if not sec_size:
            errors.append({"section": name, "error": "size == 0"})
            continue
        last_end = 0
        for i in range(vlen):
            var_type, off, size = struct.unpack_from("<III", blob, pos + i * 12)
            variables += 1
            if var_type not in types or types[var_type]["kind"] != 14:
                errors.append({"section": name, "index": i, "type": var_type,
                               "error": "member is not BTF_KIND_VAR"})
            if not size or size > sec_size:
                errors.append({"section": name, "type": var_type, "offset": off,
                               "size": size, "error": "invalid size"})
            if off < last_end or off >= sec_size:
                errors.append({"section": name, "type": var_type, "offset": off,
                               "size": size, "previous_end": last_end,
                               "error": "invalid offset"})
            if off + size > sec_size:
                errors.append({"section": name, "type": var_type, "offset": off,
                               "size": size, "error": "offset+size out of range"})
            last_end = off + size
    result = {"file": str(vmlinux), "type_count": len(types),
              "datasec_sections": len(datasecs), "datasec_variables": variables,
              "errors": errors}
    print(json.dumps({k: v for k, v in result.items() if k != "errors"}
                     if not errors else result))
    if errors:
        raise SystemExit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} <vmlinux>")
    validate(Path(sys.argv[1]))
