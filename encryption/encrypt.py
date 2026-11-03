#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""encrypt.py — 本地加密工具：明文目录 → 密文目录 + 清单（两者原子地一起重新生成）

用法：
  export OOEP_PASSPHRASE='...'     # 或 --passphrase-file，或交互式输入
  python3 encrypt.py --src <明文根目录> --out <密文目录> --manifest <manifest.tsv>

注意：--src 内部各文件的"相对路径"必须等于这些文件在仓库中的原有路径，
CI 解密后才能落回原位（相对 import / require、相对 CWD 的数据输出才不会断）。
例如脚本原本在仓库的 src/fetch.py，则 --src 应指向包含 src/ 子目录的那个根。
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys

import ooep_crypto as C


def get_passphrase(args) -> bytes:
    if args.passphrase_file:
        with open(args.passphrase_file, "rb") as f:
            return f.read().rstrip(b"\r\n")
    env = os.environ.get("OOEP_PASSPHRASE")
    if env:
        return env.encode("utf-8")
    import getpass
    return getpass.getpass("passphrase: ").encode("utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="ooep 加密工具（明文目录 → 密文 + 清单）")
    ap.add_argument("--src", required=True, help="明文根目录（内部相对路径=仓库内路径）")
    ap.add_argument("--out", required=True, help="密文输出目录（每个文件加 .enc 后缀）")
    ap.add_argument("--manifest", required=True, help="清单文件路径（整体重新生成）")
    ap.add_argument("--passphrase-file", help="从文件读取口令（否则用环境变量或交互输入）")
    args = ap.parse_args()

    passphrase = get_passphrase(args)
    if not passphrase:
        print("FAIL: 口令为空", file=sys.stderr)
        return 2

    rows = []
    count = 0
    for dirpath, dirnames, filenames in os.walk(args.src):
        dirnames[:] = sorted(d for d in dirnames if d != ".git")
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, args.src).replace(os.sep, "/")
            with open(full, "rb") as f:
                data = f.read()
            blob, check_key = C.encrypt_blob(passphrase, rel, data)
            outp = os.path.join(args.out, rel.replace("/", os.sep) + ".enc")
            d = os.path.dirname(outp)
            if d:
                os.makedirs(d, exist_ok=True)
            with open(outp, "wb") as f:
                f.write(blob)
            rows.append((rel, hashlib.sha256(blob).hexdigest(),
                         C.plaintext_mac(check_key, data)))
            count += 1
            print(f"ENC {rel}")
    C.write_manifest(args.manifest, rows)
    print(f"OK: {count} 个文件 → {args.out}；清单 → {args.manifest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
