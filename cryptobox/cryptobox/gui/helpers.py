"""Shared Tkinter helpers."""

import threading
import tkinter as tk
from tkinter import messagebox

from ..core.encoding import encode as _encode
from ..core.encoding import decode as _decode


def make_text(parent, height=6, readonly=False):
    widget = tk.Text(parent, height=height, wrap="word", undo=not readonly,
                     borderwidth=1, relief="solid")
    if readonly:
        widget.configure(state="disabled")
    return widget


def get_text(widget) -> str:
    if str(widget.cget("state")) == "disabled":
        return widget.get("1.0", "end-1c")
    return widget.get("1.0", "end-1c")


def set_text(widget, content: str):
    state = str(widget.cget("state"))
    if state == "disabled":
        widget.configure(state="normal")
    widget.delete("1.0", "end")
    widget.insert("1.0", content)
    if state == "disabled":
        widget.configure(state="disabled")


def encode_bytes(data: bytes, fmt: str) -> str:
    return _encode(data, fmt)


def decode_text(text: str, fmt: str) -> bytes:
    return _decode(text, fmt)


def run_task(root, work, on_success, on_error=None):
    def worker():
        try:
            result = work()
        except Exception as exc:  # noqa: BLE001 - surfaced to the user
            if on_error is not None:
                root.after(0, lambda e=exc: on_error(e))
            return
        root.after(0, lambda r=result: on_success(r))

    threading.Thread(target=worker, daemon=True).start()


def show_error(parent, message):
    messagebox.showerror("错误", str(message), parent=parent)


def show_info(parent, message):
    messagebox.showinfo("提示", str(message), parent=parent)
