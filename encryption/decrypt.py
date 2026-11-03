#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""decrypt.py — CI 端解密 / 校验 / 清理工具（零依赖，仅 Python3 标准库）

子命令：
  decrypt   校验并还原明文到 --out（默认；拒绝覆盖已存在的文件，--force 允许）
            --verify-only 只校验不落盘
  clean     删除清单列出的明文文件，并自底向上清理因此变空的目录

口令来自环境变量 OOEP_PASSPHRASE 或 --passphrase-file，绝不出现在命令行参数里。
所有失败都以非 0 退出码结束；错误输出只含路径与失败原因，绝不含明文内容。
解密产物统一 umask 077（目录 700 / 文件 600）。
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys

import ooep_crypto as C


def get_passphrase(args) -> bytes:
    if getattr(args, "passphrase_file", None):
        with open(args.passphrase_file, "rb") as f:
            return f.read().rstrip(b"\r\n")
    env = os.environ.get("OOEP_PASSPHRASE")
    if env:
        return env.encode("utf-8")
    print("FAIL: 未提供口令（环境变量 OOEP_PASSPHRASE 或 --passphrase-file）", file=sys.stderr)
    sys.exit(3)


def _enc_path(enc_dir: str, rel: str) -> str:
    return os.path.join(enc_dir, rel.replace("/", os.sep) + ".enc")


def cmd_decrypt(args) -> int:
    os.umask(0o077)
    manifest = C.read_manifest(args.manifest)
    if not manifest:
        print("FAIL: 清单为空", file=sys.stderr)
        return 3

    expected = {_enc_path(args.enc, rel) for rel in manifest}
    found = set()
    for dirpath, dirnames, filenames in os.walk(args.enc):
        dirnames[:] = sorted(d for d in dirnames if d != ".git")
        for name in filenames:
            if name.endswith(".enc"):
                found.add(os.path.join(dirpath, name))
    for p in sorted(found - expected):
        print(f"FAIL: 存在未登记进清单的密文: {p}", file=sys.stderr)
    for p in sorted(expected - found):
        print(f"FAIL: 清单登记的密文文件缺失: {p}", file=sys.stderr)
    if found != expected:
        return 3

    passphrase = get_passphrase(args)
    n = 0
    for rel in sorted(manifest):
        sha_want, mac_want = manifest[rel]
        path = _enc_path(args.enc, rel)
        with open(path, "rb") as f:
            blob = f.read()
        if hashlib.sha256(blob).hexdigest() != sha_want:
            print(f"FAIL[{rel}] 密文文件 sha256 与清单不符"
                  "（加密后被改动，或清单未随密文一起重新生成）", file=sys.stderr)
            return 3
        try:
            pt, check_key = C.decrypt_blob(blob, passphrase, rel)
        except C.CryptoError as e:
            print(f"FAIL[{rel}] {e}", file=sys.stderr)
            return 3
        if C.plaintext_mac(check_key, pt) != mac_want:
            print(f"FAIL[{rel}] 明文哈希校验失败：密文与清单不同步"
                  "（源码改动后未重新加密？）请用 encrypt.py 一起重新生成", file=sys.stderr)
            return 3
        if not args.verify_only:
            dest = os.path.join(args.out, rel.replace("/", os.sep))
            if os.path.exists(dest) and not args.force:
                print(f"FAIL[{rel}] 目标已存在，拒绝覆盖（仓库里不应有同名明文；"
                      f"本地重复解密可加 --force）: {dest}", file=sys.stderr)
                return 3
            d = os.path.dirname(dest)
            if d:
                os.makedirs(d, mode=0o700, exist_ok=True)
            fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(pt)
        n += 1
        print(f"{'VER' if args.verify_only else 'DEC'} {rel}")
    print(f"OK: {n} 个文件" + ("校验通过" if args.verify_only else f"已还原到 {args.out}"))
    return 0


def cmd_clean(args) -> int:
    manifest = C.read_manifest(args.manifest)
    removed = 0
    dirs = set()
    for rel in manifest:
        dest = os.path.join(args.out, rel.replace("/", os.sep))
        if os.path.isfile(dest):
            os.remove(dest)
            removed += 1
        d = os.path.dirname(dest)
        while d:
            dirs.add(d)
            parent = os.path.dirname(d)
            if parent == d:
                break
            d = parent
    for d in sorted(dirs, key=lambda p: p.count(os.sep), reverse=True):
        try:
            os.rmdir(d)
        except OSError:
            pass  # 非空目录（例如还有数据文件）保留
    print(f"OK: 已删除 {removed} 个明文文件")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="ooep 解密/校验/清理工具")
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("decrypt", help="校验并还原明文")
    d.add_argument("--enc", required=True, help="密文目录")
    d.add_argument("--manifest", required=True, help="清单文件")
    d.add_argument("--out", required=True, help="明文还原目录（仓库根）")
    d.add_argument("--force", action="store_true", help="允许覆盖已存在文件")
    d.add_argument("--verify-only", action="store_true", help="只校验不落盘")
    d.add_argument("--passphrase-file")

    c = sub.add_parser("clean", help="删除已还原的明文")
    c.add_argument("--manifest", required=True)
    c.add_argument("--out", required=True)

    args = ap.parse_args(argv)
    try:
        return cmd_decrypt(args) if args.cmd == "decrypt" else cmd_clean(args)
    except C.CryptoError as e:
        print(f"FAIL: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
