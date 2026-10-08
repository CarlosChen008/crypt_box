"""Hash computation tab."""

import tkinter as tk
from tkinter import ttk, filedialog

from ..core import hashes
from . import helpers


def build(parent):
    frame = ttk.Frame(parent, padding=12)
    frame.columnconfigure(1, weight=1)
    frame.rowconfigure(4, weight=1)

    algo = tk.StringVar(value=hashes.supported()[0])
    ttk.Label(frame, text="算法").grid(row=0, column=0, sticky="w", pady=4)
    ttk.Combobox(frame, textvariable=algo, values=hashes.supported(),
                 state="readonly", width=16).grid(row=0, column=1, sticky="w", pady=4)

    ttk.Label(frame, text="输入文本").grid(row=1, column=0, columnspan=2, sticky="w")
    text_in = helpers.make_text(frame, height=6)
    text_in.grid(row=2, column=0, columnspan=2, sticky="nsew")

    buttons = ttk.Frame(frame)
    buttons.grid(row=3, column=0, columnspan=2, sticky="w", pady=6)

    status = tk.StringVar(value="")
    result = helpers.make_text(frame, height=4, readonly=True)
    result.grid(row=5, column=0, columnspan=2, sticky="nsew")

    ttk.Label(frame, text="摘要结果 (hex)").grid(row=4, column=0, columnspan=2, sticky="sw")

    def compute_text():
        try:
            digest = hashes.digest_hex(algo.get(), helpers.get_text(text_in).encode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            helpers.show_error(frame, exc)
            return
        helpers.set_text(result, digest)
        status.set("完成")

    def compute_file():
        path = filedialog.askopenfilename(parent=frame)
        if not path:
            return
        status.set("计算中...")
        helpers.run_task(
            frame.winfo_toplevel(),
            lambda: hashes.hash_file(algo.get(), path),
            lambda digest: (helpers.set_text(result, digest), status.set("完成")),
            lambda exc: (helpers.show_error(frame, exc), status.set("失败")),
        )

    def clear():
        helpers.set_text(text_in, "")
        helpers.set_text(result, "")
        status.set("")

    def copy_result():
        frame.clipboard_clear()
        frame.clipboard_append(helpers.get_text(result))
        status.set("已复制")

    ttk.Button(buttons, text="计算文本摘要", command=compute_text).pack(side="left", padx=3)
    ttk.Button(buttons, text="从文件计算摘要", command=compute_file).pack(side="left", padx=3)
    ttk.Button(buttons, text="复制结果", command=copy_result).pack(side="left", padx=3)
    ttk.Button(buttons, text="清空", command=clear).pack(side="left", padx=3)

    ttk.Label(frame, textvariable=status, foreground="#555").grid(
        row=6, column=0, columnspan=2, sticky="w", pady=4)

    return frame
