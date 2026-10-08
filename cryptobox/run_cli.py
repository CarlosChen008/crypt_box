#!/usr/bin/env python3
"""Command line front-end for the Cryptobox primitives."""

import argparse
import sys

from cryptobox import crack
from cryptobox.core import encoding, hashes, hill, rsa, symmetric


def cmd_hash(args):
    if args.file:
        with open(args.file, "rb") as handle:
            data = handle.read()
    else:
        data = args.text.encode("utf-8")
    print(hashes.digest_hex(args.algo, data))


def cmd_crack(args):
    if args.wordlist:
        result = crack.crack_dictionary_file(args.algo, args.hash, args.wordlist, args.salt)
    elif args.brute:
        result = crack.crack_brute_force(args.algo, args.hash, args.brute,
                                         args.min_len, args.max_len, args.salt)
    else:
        result = crack.crack_dictionary(args.algo, args.hash, crack.default_wordlist(), args.salt)
    if result["found"]:
        print("found: %s (%d attempts)" % (result["plaintext"], result["attempts"]))
    else:
        print("not found (%d attempts)" % result["attempts"])
        sys.exit(1)


def cmd_encrypt(args):
    data = args.text.encode("utf-8")
    if args.algo == "hill":
        blob = hill.encrypt(args.text, hill.parse_key(args.key))
        print(blob)
        return
    if args.algo == "aes":
        blob = symmetric.encrypt_aes(args.key, data, args.mode)
    elif args.algo == "des":
        blob = symmetric.encrypt_des(args.key, data)
    elif args.algo == "3des":
        blob = symmetric.encrypt_3des(args.key, data)
    else:
        raise SystemExit("unknown algorithm")
    print(encoding.encode(blob, args.format))


def cmd_decrypt(args):
    if args.algo == "hill":
        print(hill.decrypt(args.text, hill.parse_key(args.key)))
        return
    blob = encoding.decode(args.text, args.format)
    if args.algo == "aes":
        plain = symmetric.decrypt_aes(args.key, blob, args.mode)
    elif args.algo == "des":
        plain = symmetric.decrypt_des(args.key, blob)
    elif args.algo == "3des":
        plain = symmetric.decrypt_3des(args.key, blob)
    else:
        raise SystemExit("unknown algorithm")
    print(plain.decode("utf-8", errors="replace"))


def cmd_rsa_gen(args):
    key = rsa.generate_keypair(args.bits)
    print("# public key")
    print(rsa.format_public((key.n, key.e)), end="")
    print("# private key")
    print(rsa.format_private(key), end="")


def cmd_rsa_encrypt(args):
    public = _read_key(args)
    public = rsa.parse_public(public)
    message = args.text.encode("utf-8")
    ct = rsa.oaep_encrypt(public, message) if args.oaep else rsa.pkcs1v15_encrypt(public, message)
    print(encoding.encode(ct, "BASE64"))


def cmd_rsa_decrypt(args):
    private = rsa.parse_private(_read_key(args))
    ct = encoding.decode(args.text, "BASE64")
    pt = rsa.oaep_decrypt(private, ct) if args.oaep else rsa.pkcs1v15_decrypt(private, ct)
    print(pt.decode("utf-8", errors="replace"))


def cmd_rsa_sign(args):
    private = rsa.parse_private(_read_key(args))
    signature = rsa.sign(private, args.text.encode("utf-8"))
    print(encoding.encode(signature, "BASE64"))


def cmd_rsa_verify(args):
    public = rsa.parse_public(_read_key(args))
    signature = encoding.decode(args.signature, "BASE64")
    ok = rsa.verify(public, args.text.encode("utf-8"), signature)
    print("valid" if ok else "invalid")
    sys.exit(0 if ok else 1)


def _read_key(args):
    if getattr(args, "key_file", None):
        with open(args.key_file, "r", encoding="utf-8") as handle:
            return handle.read()
    if getattr(args, "key", None):
        return args.key
    raise SystemExit("provide --key or --key-file")


def build_parser():
    parser = argparse.ArgumentParser(prog="cryptobox", description="Cryptobox CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("hash", help="compute a hash")
    p.add_argument("algo", choices=hashes.supported())
    p.add_argument("text", nargs="?", default="")
    p.add_argument("--file")
    p.set_defaults(func=cmd_hash)

    p = sub.add_parser("crack", help="recover a password from its hash")
    p.add_argument("algo", choices=hashes.supported())
    p.add_argument("hash")
    p.add_argument("--salt", default="")
    p.add_argument("--wordlist")
    p.add_argument("--brute", help="character set for brute force")
    p.add_argument("--min-len", type=int, default=1)
    p.add_argument("--max-len", type=int, default=4)
    p.set_defaults(func=cmd_crack)

    for name, fn in (("encrypt", cmd_encrypt), ("decrypt", cmd_decrypt)):
        p = sub.add_parser(name)
        p.add_argument("algo", choices=["aes", "des", "3des", "hill"])
        p.add_argument("key", help="passphrase or Hill key matrix")
        p.add_argument("text")
        p.add_argument("--mode", default="CTR", choices=["CTR", "CBC"])
        p.add_argument("--format", default="BASE64", choices=["BASE64", "HEX"])
        p.set_defaults(func=fn)

    p = sub.add_parser("rsa-gen")
    p.add_argument("bits", type=int, nargs="?", default=2048)
    p.set_defaults(func=cmd_rsa_gen)

    p = sub.add_parser("rsa-encrypt")
    p.add_argument("text")
    _add_key_args(p)
    p.add_argument("--oaep", action="store_true")
    p.set_defaults(func=cmd_rsa_encrypt)

    p = sub.add_parser("rsa-decrypt")
    p.add_argument("text")
    _add_key_args(p)
    p.add_argument("--oaep", action="store_true")
    p.set_defaults(func=cmd_rsa_decrypt)

    p = sub.add_parser("rsa-sign")
    p.add_argument("text")
    _add_key_args(p)
    p.set_defaults(func=cmd_rsa_sign)

    p = sub.add_parser("rsa-verify")
    p.add_argument("text")
    p.add_argument("signature")
    _add_key_args(p)
    p.set_defaults(func=cmd_rsa_verify)

    return parser


def _add_key_args(parser):
    parser.add_argument("--key")
    parser.add_argument("--key-file")


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
