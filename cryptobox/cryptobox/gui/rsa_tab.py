"""Public-key (RSA) tab."""

import base64
import tkinter as tk
from tkinter import ttk

from ..core import rsa
from . import helpers


def build(parent):
    frame = ttk.Frame(parent, padding=12)
    frame.columnconfigure(0, weight=1)
    frame.rowconfigure(3, weight=1)
    frame.rowconfigure(7, weight=1)

    top = ttk.Frame(frame)
    top.grid(row=0, column=0, sticky="ew")
    key_size = tk.StringVar(value="2048")
    ttk.Label(top, text="密钥长度 (bits)").pack(side="left")
    ttk.Combobox(top, textvariable=key_size, values=["1024", "2048", "3072", "4096"],
                 state="readonly", width=8).pack(side="left", padx=6)
    status = tk.StringVar(value="")
    ttk.Label(top, textvariable=status, foreground="#555").pack(side="left", padx=10)

    pub_text = helpers.make_text(frame, height=4)
    priv_text = helpers.make_text(frame, height=4)

    def generate():
        try:
            bits = int(key_size.get())
        except ValueError:
            return
        status.set("正在生成密钥，请稍候...")

        def work():
            key = rsa.generate_keypair(bits)
            return key

        def done(key):
            helpers.set_text(pub_text, rsa.format_public((key.n, key.e)))
            helpers.set_text(priv_text, rsa.format_private(key))
            status.set("密钥生成完成")

        def failed(exc):
            helpers.show_error(frame, exc)
            status.set("生成失败")

        helpers.run_task(frame.winfo_toplevel(), work, done, failed)

    ttk.Button(top, text="生成密钥对", command=generate).pack(side="left")

    ttk.Label(frame, text="公钥").grid(row=1, column=0, sticky="w", pady=(8, 0))
    pub_text.grid(row=3, column=0, sticky="nsew")
    ttk.Label(frame, text="私钥").grid(row=4, column=0, sticky="w", pady=(8, 0))
    priv_text.grid(row=5, column=0, sticky="nsew")

    scheme = tk.StringVar(value="OAEP")
    scheme_row = ttk.Frame(frame)
    scheme_row.grid(row=6, column=0, sticky="w", pady=8)
    ttk.Label(scheme_row, text="填充方案").pack(side="left")
    ttk.Radiobutton(scheme_row, text="OAEP-SHA256 (推荐)", variable=scheme,
                    value="OAEP").pack(side="left", padx=6)
    ttk.Radiobutton(scheme_row, text="PKCS#1 v1.5", variable=scheme,
                    value="V15").pack(side="left", padx=6)

    ttk.Label(frame, text="明文 / 待签名数据").grid(row=8, column=0, sticky="w")
    plain_text = helpers.make_text(frame, height=4)
    plain_text.grid(row=9, column=0, sticky="nsew")

    ttk.Label(frame, text="密文 / 签名 (BASE64)").grid(row=10, column=0, sticky="w", pady=(8, 0))
    cipher_text = helpers.make_text(frame, height=4)
    cipher_text.grid(row=11, column=0, sticky="nsew")

    verify_label = tk.StringVar(value="")

    def load_public():
        return rsa.parse_public(helpers.get_text(pub_text))

    def load_private():
        return rsa.parse_private(helpers.get_text(priv_text))

    def do_encrypt():
        try:
            public = load_public()
            message = helpers.get_text(plain_text).encode("utf-8")
            if scheme.get() == "OAEP":
                ct = rsa.oaep_encrypt(public, message)
            else:
                ct = rsa.pkcs1v15_encrypt(public, message)
            helpers.set_text(cipher_text, base64.b64encode(ct).decode("ascii"))
            verify_label.set("加密完成")
        except Exception as exc:  # noqa: BLE001
            helpers.show_error(frame, exc)

    def do_decrypt():
        try:
            private = load_private()
            ct = base64.b64decode("".join(helpers.get_text(cipher_text).split()))
            if scheme.get() == "OAEP":
                pt = rsa.oaep_decrypt(private, ct)
            else:
                pt = rsa.pkcs1v15_decrypt(private, ct)
            helpers.set_text(plain_text, pt.decode("utf-8", errors="replace"))
            verify_label.set("解密完成")
        except Exception as exc:  # noqa: BLE001
            helpers.show_error(frame, exc)

    def do_sign():
        try:
            private = load_private()
            signature = rsa.sign(private, helpers.get_text(plain_text).encode("utf-8"))
            helpers.set_text(cipher_text, base64.b64encode(signature).decode("ascii"))
            verify_label.set("签名完成")
        except Exception as exc:  # noqa: BLE001
            helpers.show_error(frame, exc)

    def do_verify():
        try:
            public = load_public()
            signature = base64.b64decode("".join(helpers.get_text(cipher_text).split()))
            ok = rsa.verify(public, helpers.get_text(plain_text).encode("utf-8"), signature)
            verify_label.set("验证结果: " + ("签名有效" if ok else "签名无效"))
        except Exception as exc:  # noqa: BLE001
            helpers.show_error(frame, exc)

    buttons = ttk.Frame(frame)
    buttons.grid(row=12, column=0, sticky="w", pady=8)
    ttk.Button(buttons, text="加密 (公钥)", command=do_encrypt).pack(side="left", padx=3)
    ttk.Button(buttons, text="解密 (私钥)", command=do_decrypt).pack(side="left", padx=3)
    ttk.Button(buttons, text="签名 (私钥)", command=do_sign).pack(side="left", padx=3)
    ttk.Button(buttons, text="验证签名 (公钥)", command=do_verify).pack(side="left", padx=3)

    ttk.Label(frame, textvariable=verify_label, foreground="#0a6").grid(
        row=13, column=0, sticky="w")

    return frame
