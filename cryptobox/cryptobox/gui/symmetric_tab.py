"""Symmetric encryption tab: AES, DES, 3DES and the Hill cipher."""

import tkinter as tk
from tkinter import ttk

from ..core import hill
from ..core import symmetric
from . import helpers

ALGORITHMS = [
    "AES-256 CTR + HMAC (推荐)",
    "AES-256 CBC",
    "DES CBC (教学, 不安全)",
    "3DES CBC (教学, 不安全)",
    "Hill 密码 (教学)",
]


def build(parent):
    frame = ttk.Frame(parent, padding=12)
    frame.columnconfigure(1, weight=1)
    frame.rowconfigure(7, weight=1)
    frame.rowconfigure(9, weight=1)

    algo = tk.StringVar(value=ALGORITHMS[0])
    passphrase = tk.StringVar()
    fmt = tk.StringVar(value="BASE64")

    ttk.Label(frame, text="算法").grid(row=0, column=0, sticky="w", pady=3)
    ttk.Combobox(frame, textvariable=algo, values=ALGORITHMS, state="readonly",
                 width=32).grid(row=0, column=1, sticky="w", pady=3)

    ttk.Label(frame, text="口令").grid(row=1, column=0, sticky="w", pady=3)
    ttk.Entry(frame, textvariable=passphrase, show="*").grid(
        row=1, column=1, sticky="ew", pady=3)

    default_key = hill.key_string(hill.random_key(2))
    hill_key = tk.StringVar(value=default_key)
    ttk.Label(frame, text="Hill 密钥矩阵").grid(row=2, column=0, sticky="w", pady=3)
    key_row = ttk.Frame(frame)
    key_row.grid(row=2, column=1, sticky="ew", pady=3)
    key_row.columnconfigure(0, weight=1)
    ttk.Entry(key_row, textvariable=hill_key).grid(row=0, column=0, sticky="ew")

    def random_key():
        hill_key.set(hill.key_string(hill.random_key(2)))

    ttk.Button(key_row, text="随机生成", command=random_key).grid(row=0, column=1, padx=4)

    ttk.Label(frame, text="编码格式").grid(row=3, column=0, sticky="w", pady=3)
    fmt_frame = ttk.Frame(frame)
    fmt_frame.grid(row=3, column=1, sticky="w")
    ttk.Radiobutton(fmt_frame, text="BASE64", variable=fmt, value="BASE64").pack(side="left")
    ttk.Radiobutton(fmt_frame, text="HEX", variable=fmt, value="HEX").pack(side="left", padx=8)

    status = tk.StringVar(value="")

    ttk.Label(frame, text="输入 (明文 / 密文 / 字母文本)").grid(
        row=4, column=0, columnspan=2, sticky="w")
    text_in = helpers.make_text(frame, height=6)
    text_in.grid(row=7, column=0, columnspan=2, sticky="nsew", pady=(0, 6))

    ttk.Label(frame, text="输出").grid(row=8, column=0, columnspan=2, sticky="w")
    text_out = helpers.make_text(frame, height=6, readonly=True)
    text_out.grid(row=9, column=0, columnspan=2, sticky="nsew")

    def do_encrypt():
        try:
            selected = algo.get()
            if selected.startswith("AES-256 CTR"):
                blob = symmetric.encrypt_aes(passphrase.get(), helpers.get_text(text_in).encode("utf-8"), "CTR")
                helpers.set_text(text_out, helpers.encode_bytes(blob, fmt.get()))
            elif selected.startswith("AES-256 CBC"):
                blob = symmetric.encrypt_aes(passphrase.get(), helpers.get_text(text_in).encode("utf-8"), "CBC")
                helpers.set_text(text_out, helpers.encode_bytes(blob, fmt.get()))
            elif selected.startswith("DES"):
                blob = symmetric.encrypt_des(passphrase.get(), helpers.get_text(text_in).encode("utf-8"))
                helpers.set_text(text_out, helpers.encode_bytes(blob, fmt.get()))
            elif selected.startswith("3DES"):
                blob = symmetric.encrypt_3des(passphrase.get(), helpers.get_text(text_in).encode("utf-8"))
                helpers.set_text(text_out, helpers.encode_bytes(blob, fmt.get()))
            else:
                key = hill.parse_key(hill_key.get())
                helpers.set_text(text_out, hill.encrypt(helpers.get_text(text_in), key))
            status.set("加密完成")
        except Exception as exc:  # noqa: BLE001
            helpers.show_error(frame, exc)

    def do_decrypt():
        try:
            selected = algo.get()
            if selected.startswith("AES-256 CTR"):
                blob = helpers.decode_text(helpers.get_text(text_in), fmt.get())
                helpers.set_text(text_out, symmetric.decrypt_aes(passphrase.get(), blob, "CTR").decode("utf-8"))
            elif selected.startswith("AES-256 CBC"):
                blob = helpers.decode_text(helpers.get_text(text_in), fmt.get())
                helpers.set_text(text_out, symmetric.decrypt_aes(passphrase.get(), blob, "CBC").decode("utf-8"))
            elif selected.startswith("DES"):
                blob = helpers.decode_text(helpers.get_text(text_in), fmt.get())
                helpers.set_text(text_out, symmetric.decrypt_des(passphrase.get(), blob).decode("utf-8"))
            elif selected.startswith("3DES"):
                blob = helpers.decode_text(helpers.get_text(text_in), fmt.get())
                helpers.set_text(text_out, symmetric.decrypt_3des(passphrase.get(), blob).decode("utf-8"))
            else:
                key = hill.parse_key(hill_key.get())
                helpers.set_text(text_out, hill.decrypt(helpers.get_text(text_in), key))
            status.set("解密完成")
        except Exception as exc:  # noqa: BLE001
            helpers.show_error(frame, exc)

    def swap():
        helpers.set_text(text_in, helpers.get_text(text_out))
        status.set("")

    def clear():
        helpers.set_text(text_in, "")
        helpers.set_text(text_out, "")
        status.set("")

    def copy_out():
        frame.clipboard_clear()
        frame.clipboard_append(helpers.get_text(text_out))
        status.set("已复制")

    controls = ttk.Frame(frame)
    controls.grid(row=5, column=0, columnspan=2, sticky="w", pady=6)
    ttk.Button(controls, text="加密", command=do_encrypt).pack(side="left", padx=3)
    ttk.Button(controls, text="解密", command=do_decrypt).pack(side="left", padx=3)
    ttk.Button(controls, text="结果 -> 输入", command=swap).pack(side="left", padx=3)
    ttk.Button(controls, text="复制结果", command=copy_out).pack(side="left", padx=3)
    ttk.Button(controls, text="清空", command=clear).pack(side="left", padx=3)

    ttk.Label(frame, textvariable=status, foreground="#555").grid(
        row=10, column=0, columnspan=2, sticky="w", pady=4)

    return frame
