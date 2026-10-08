"""Hash cracking tab (dictionary + brute force)."""

import threading
import tkinter as tk
from tkinter import ttk, filedialog

from .. import crack
from . import helpers


def build(parent):
    frame = ttk.Frame(parent, padding=12)
    frame.columnconfigure(1, weight=1)

    algo = tk.StringVar(value="MD5")
    target = tk.StringVar()
    salt = tk.StringVar()
    mode = tk.StringVar(value="dictionary")

    ttk.Label(frame, text="算法").grid(row=0, column=0, sticky="w", pady=3)
    ttk.Combobox(frame, textvariable=algo, values=["MD5", "SHA1", "SHA256"],
                 state="readonly", width=16).grid(row=0, column=1, sticky="w", pady=3)

    ttk.Label(frame, text="目标哈希").grid(row=1, column=0, sticky="w", pady=3)
    ttk.Entry(frame, textvariable=target).grid(row=1, column=1, sticky="ew", pady=3)

    ttk.Label(frame, text="盐 (可选)").grid(row=2, column=0, sticky="w", pady=3)
    ttk.Entry(frame, textvariable=salt).grid(row=2, column=1, sticky="ew", pady=3)

    ttk.Label(frame, text="破解方式").grid(row=3, column=0, sticky="w", pady=3)
    mode_frame = ttk.Frame(frame)
    mode_frame.grid(row=3, column=1, sticky="w")
    ttk.Radiobutton(mode_frame, text="字典攻击", variable=mode,
                    value="dictionary").pack(side="left", padx=4)
    ttk.Radiobutton(mode_frame, text="暴力破解", variable=mode,
                    value="brute").pack(side="left", padx=4)

    dict_frame = ttk.LabelFrame(frame, text="字典设置", padding=8)
    dict_frame.grid(row=4, column=0, columnspan=2, sticky="ew", pady=6)
    builtin_var = tk.BooleanVar(value=True)
    wordlist = {"words": []}
    word_info = tk.StringVar(value="未加载外部字典")

    ttk.Checkbutton(dict_frame, text="使用内置常用密码表", variable=builtin_var).pack(anchor="w")

    def choose_wordlist():
        path = filedialog.askopenfilename(parent=frame)
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                words = [line.strip() for line in handle if line.strip()]
        except Exception as exc:  # noqa: BLE001
            helpers.show_error(frame, exc)
            return
        wordlist["words"] = words
        word_info.set("已加载 %d 个候选词" % len(words))

    ttk.Button(dict_frame, text="选择字典文件", command=choose_wordlist).pack(
        side="left", pady=4)
    ttk.Label(dict_frame, textvariable=word_info).pack(side="left", padx=8)

    brute_frame = ttk.LabelFrame(frame, text="暴力破解设置", padding=8)
    brute_frame.grid(row=5, column=0, columnspan=2, sticky="ew", pady=6)
    charset = tk.StringVar(value="abcdefghijklmnopqrstuvwxyz0123456789")
    min_len = tk.StringVar(value="1")
    max_len = tk.StringVar(value="4")
    ttk.Label(brute_frame, text="字符集").grid(row=0, column=0, sticky="w")
    ttk.Entry(brute_frame, textvariable=charset, width=40).grid(row=0, column=1, sticky="w", pady=2)
    ttk.Label(brute_frame, text="最小长度").grid(row=1, column=0, sticky="w")
    ttk.Spinbox(brute_frame, from_=1, to=12, textvariable=min_len, width=5).grid(
        row=1, column=1, sticky="w", pady=2)
    ttk.Label(brute_frame, text="最大长度").grid(row=2, column=0, sticky="w")
    ttk.Spinbox(brute_frame, from_=1, to=12, textvariable=max_len, width=5).grid(
        row=2, column=1, sticky="w", pady=2)

    controls = ttk.Frame(frame)
    controls.grid(row=6, column=0, columnspan=2, sticky="ew", pady=6)
    progress = ttk.Progressbar(controls, mode="indeterminate", length=180)
    attempts = tk.StringVar(value="尝试次数: 0")
    result = tk.StringVar(value="")
    progress.pack(side="left")

    stop_event = threading.Event()
    running = {"value": False}

    def progress_cb(count):
        frame.after(0, lambda: attempts.set("尝试次数: %d" % count))

    def start():
        if running["value"]:
            return
        if not target.get().strip():
            helpers.show_error(frame, "请输入目标哈希值")
            return

        use_dict = mode.get() == "dictionary"
        if use_dict:
            if builtin_var.get():
                words = crack.default_wordlist()
            elif wordlist["words"]:
                words = wordlist["words"]
            else:
                helpers.show_error(frame, "请选择字典文件，或勾选内置常用密码表")
                return
            work = lambda: crack.crack_dictionary(
                algo.get(), target.get(), words, salt.get(), progress_cb, stop_event)
        else:
            try:
                low = int(min_len.get())
                high = int(max_len.get())
            except ValueError:
                helpers.show_error(frame, "长度必须是整数")
                return
            work = lambda: crack.crack_brute_force(
                algo.get(), target.get(), charset.get(), low, high,
                salt.get(), progress_cb, stop_event)

        stop_event.clear()
        running["value"] = True
        progress.start(12)
        result.set("破解中...")
        attempts.set("尝试次数: 0")

        def on_done(res):
            running["value"] = False
            progress.stop()
            attempts.set("尝试次数: %d" % res["attempts"])
            if res["found"]:
                result.set("已找到明文: %s" % res["plaintext"])
            elif res.get("stopped"):
                result.set("已停止")
            else:
                result.set("未找到匹配的明文")

        def on_error(exc):
            running["value"] = False
            progress.stop()
            helpers.show_error(frame, exc)

        helpers.run_task(frame.winfo_toplevel(), work, on_done, on_error)

    def stop():
        stop_event.set()

    ttk.Button(controls, text="开始破解", command=start).pack(side="left", padx=4)
    ttk.Button(controls, text="停止", command=stop).pack(side="left", padx=4)

    ttk.Label(frame, textvariable=attempts).grid(row=7, column=0, columnspan=2, sticky="w")
    ttk.Label(frame, textvariable=result, foreground="#0a6").grid(
        row=8, column=0, columnspan=2, sticky="w", pady=4)

    return frame
