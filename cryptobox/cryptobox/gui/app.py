"""Tkinter application entry point."""

import tkinter as tk
from tkinter import ttk

from . import crack_tab, hash_tab, rsa_tab, symmetric_tab


def main():
    root = tk.Tk()
    root.title("密码学工具箱 Cryptobox")
    root.minsize(840, 700)

    try:
        ttk.Style().theme_use("clam")
    except tk.TclError:
        pass

    notebook = ttk.Notebook(root)
    notebook.add(hash_tab.build(notebook), text="摘要计算")
    notebook.add(crack_tab.build(notebook), text="摘要破解")
    notebook.add(symmetric_tab.build(notebook), text="对称加密")
    notebook.add(rsa_tab.build(notebook), text="公钥加密")
    notebook.pack(fill="both", expand=True)

    root.mainloop()
