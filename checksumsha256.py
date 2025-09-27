#!/usr/bin/env python3
# generate_hashes.py
# Вычисляет size, sha256 и пытается извлечь версию для JAR и EXE.
# Результат записывается в hashes.json

import hashlib
import json
import os
import zipfile
import re
import sys

try:
    import pefile
except Exception:
    pefile = None

FILES = [
    "ShortcutDoctorUSB-1.0.0.jar",
    "ShortcutDoctorUSB-1.0.0.exe"
]

def sha256sum(filename, block_size=1 << 16):
    h = hashlib.sha256()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(block_size), b""):
            h.update(chunk)
    return h.hexdigest()

def parse_manifest_bytes(b):
    try:
        s = b.decode('utf-8', errors='replace')
    except Exception:
        s = str(b)
    d = {}
    # Манифесты могут содержать переносы строк и продолжения строк — для простоты берём "ключ: значение"
    for line in s.splitlines():
        if ':' in line:
            k, v = line.split(':', 1)
            d[k.strip()] = v.strip()
    return d

def parse_properties_bytes(b):
    try:
        s = b.decode('utf-8', errors='replace')
    except Exception:
        s = str(b)
    props = {}
    for line in s.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        k, v = line.split('=', 1)
        props[k.strip()] = v.strip()
    return props

def get_version_from_jar(path):
    try:
        with zipfile.ZipFile(path, 'r') as z:
            # 1) Попробуем стандартный MANIFEST.MF
            manifest_name = None
            for name in z.namelist():
                if name.upper().endswith('META-INF/MANIFEST.MF') or name.lower().endswith('meta-inf/manifest.mf'):
                    manifest_name = name
                    break
            if manifest_name:
                try:
                    mbytes = z.read(manifest_name)
                    m = parse_manifest_bytes(mbytes)
                    for key in ('Implementation-Version', 'Specification-Version', 'Bundle-Version', 'Version', 'Implementation-Version:'):
                        if key in m and m[key].strip():
                            return m[key].strip()
                except Exception:
                    pass

            # 2) Попробуем pom.properties в meta-inf/maven/*/*/pom.properties
            for name in z.namelist():
                if name.lower().startswith('meta-inf/maven/') and name.lower().endswith('pom.properties'):
                    try:
                        pbytes = z.read(name)
                        props = parse_properties_bytes(pbytes)
                        if 'version' in props and props['version'].strip():
                            return props['version'].strip()
                    except Exception:
                        pass
    except Exception as e:
        print(f"[warn] cannot read jar {path}: {e}", file=sys.stderr)
    return None

def get_version_from_exe(path):
    # 1) Попробуем pefile, если установлен
    if pefile:
        try:
            pe = pefile.PE(path)
            if hasattr(pe, 'FileInfo') and pe.FileInfo:
                for fileinfo in pe.FileInfo:
                    # StringFileInfo содержит таблицы
                    if getattr(fileinfo, 'Key', b'').decode(errors='ignore') == 'StringFileInfo':
                        for st in getattr(fileinfo, 'StringTable', []):
                            entries = getattr(st, 'entries', None)
                            if entries:
                                for k, v in entries.items():
                                    # k, v могут быть bytes
                                    try:
                                        key = k.decode('utf-8', errors='ignore') if isinstance(k, (bytes, bytearray)) else str(k)
                                        val = v.decode('utf-8', errors='ignore') if isinstance(v, (bytes, bytearray)) else str(v)
                                    except Exception:
                                        continue
                                    if key in ('FileVersion', 'ProductVersion') and val.strip():
                                        return val.strip()
        except Exception as e:
            # печатаем предупреждение, но продолжаем (не фатально)
            print(f"[warn] pefile parsing failed for {path}: {e}", file=sys.stderr)

    # 2) Резерв: поиск первой подходящей последовательности x.y.z в первых N байтах
    try:
        with open(path, 'rb') as f:
            data = f.read(200000)  # читаем первые 200 KB (обычно достаточно)
        m = re.search(rb'(\d+\.\d+\.\d+(?:\.\d+)?)', data)
        if m:
            try:
                return m.group(1).decode('ascii', errors='ignore')
            except Exception:
                return None
    except Exception as e:
        print(f"[warn] exe heuristic read failed for {path}: {e}", file=sys.stderr)

    return None

def get_version(path):
    lower = path.lower()
    if lower.endswith('.jar'):
        return get_version_from_jar(path)
    if lower.endswith('.exe'):
        return get_version_from_exe(path)
    return None

def main():
    out = {}
    for f in FILES:
        info = {"size": None, "sha256": None, "version": None}
        if not os.path.exists(f):
            print(f"[info] {f} not found -> will write nulls")
            out[f] = info
            continue

        try:
            size = os.path.getsize(f)
            info["size"] = size
        except Exception as e:
            print(f"[warn] cannot stat {f}: {e}", file=sys.stderr)

        try:
            print(f"[info] hashing {f} ...")
            info["sha256"] = sha256sum(f)
        except Exception as e:
            print(f"[warn] cannot hash {f}: {e}", file=sys.stderr)

        try:
            ver = get_version(f)
            info["version"] = ver
            if ver:
                print(f"[info] detected version for {f}: {ver}")
            else:
                print(f"[info] no version detected for {f}")
        except Exception as e:
            print(f"[warn] version detection failed for {f}: {e}", file=sys.stderr)

        out[f] = info

    with open("hashes.json", "w", encoding="utf-8") as w:
        json.dump(out, w, indent=4, ensure_ascii=False)

    print("✅ hashes.json updated")

if __name__ == "__main__":
    main()
