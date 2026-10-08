# Cryptobox（密码学工具箱 2.0）

旧版是 2014 年用 MFC/VC++ 写的启动器（`master` 分支保留）。新版用 **纯 Python**
重写，**所有密码算法都是手写实现，不调用 `hashlib` / `cryptography` /
`pycryptodome` 等任何现成加密库**，用于学习和研究。

GUI 使用 Python 标准库自带的 **Tkinter**，因此 Windows / macOS / Linux 都能运行。

## 功能

| 分组 | 功能 |
| --- | --- |
| 摘要计算 | MD5、SHA1、SHA256，支持文本与文件，输出 hex |
| 摘要破解 | 字典攻击（内置常用密码表或自选字典）、暴力破解，支持加盐 |
| 对称加密 | AES-256（CTR + HMAC，推荐）、AES-256 CBC、DES/3DES（教学）、Hill 密码 |
| 公钥加密 | RSA 生成密钥、加密/解密（OAEP 或 PKCS#1 v1.5）、签名/验证 |

## 手写实现清单

- `MD5`（RFC 1321）
- `SHA1`（FIPS 180-1）
- `SHA256`（FIPS 180-4）
- `HMAC-SHA256`（RFC 2104）
- `PBKDF2-HMAC-SHA256`（RFC 8018）
- `DES` / `Triple-DES`（FIPS 46-3，CBC 模式）
- `AES-128/192/256`（FIPS 197，CBC / CTR 模式）
- `Hill` 密码（模 26 矩阵）
- `RSA`（Miller-Rabin 素性测试、模幂、PKCS#1 v1.5、OAEP-SHA256、PKCS#1 v1.5 签名）

编码（Base64 / Hex）使用标准库，仅做数据表示，不涉及密码算法。

## 目录结构

```
cryptobox/
├── run_gui.py            # 启动图形界面
├── run_cli.py            # 命令行版本（无 GUI 环境也可用）
├── cryptobox/
│   ├── core/             # 手写密码算法
│   ├── crack/            # 字典 / 暴力破解
│   ├── gui/              # Tkinter 界面
│   └── data/             # 内置常用密码表
├── tests/                # 单元测试（标准测试向量）
└── build/                # 打包脚本
```

## 运行

需要 Python 3.8+（推荐 3.10+）。

```bash
python run_gui.py
```

Linux 上如果提示缺少 Tkinter：

```bash
sudo apt install python3-tk      # Debian/Ubuntu
sudo dnf install python3-tkinter # Fedora
```

Windows / macOS 的官方 Python 安装包已自带 Tkinter，无需额外安装。

### 命令行

```bash
python run_cli.py hash MD5 abc
python run_cli.py hash SHA256 --file somefile.bin
python run_cli.py crack MD5 5f4dcc3b5aa765d61d8327deb882cf99
python run_cli.py crack MD5 <hash> --brute abc123 --max-len 4
python run_cli.py encrypt aes "passphrase" "hello"
python run_cli.py decrypt aes "passphrase" "<base64>"
python run_cli.py encrypt hill "6 24 1 13 16 10 20 17 15" ACT
python run_cli.py rsa-gen 2048 > key.txt
python run_cli.py rsa-encrypt "secret" --key-file key.txt --oaep
```

## 打包为单文件可执行程序

需要额外安装 [PyInstaller](https://pyinstaller.org/)（仅打包用，运行不需要）：

```bash
python -m pip install pyinstaller
```

- Windows：双击或运行 `build/build_windows.bat`，生成 `dist/Cryptobox.exe`
- Linux：`bash build/build_linux.sh`
- macOS：`bash build/build_macos.sh`

## 测试

```bash
python -m unittest discover -s tests -t . -v
```

测试覆盖 MD5/SHA1/SHA256、HMAC、PBKDF2、DES、AES、Hill、RSA 的标准测试向量与
加解密往返。

## 安全说明（重要）

这是**教学/研究**工具，部分算法和参数是为演示目的选择的，请勿用于生产环境：

- MD5、SHA1、DES、3DES 已经不安全，仅用于学习经典算法。
- AES 模式下推荐 CTR + HMAC-SHA256（先加密后认证）；CBC 模式未提供认证。
- PBKDF2 迭代次数为 4096（纯 Python 实现较慢）；生产环境应使用更高迭代次数或
  Argon2。
- RSA 密钥建议 2048 位以上；OAEP 需要密钥至少 528 位（本工具界面最小提供 1024）。
- 密钥采用自定义的 PEM 风格文本格式，**不兼容** OpenSSL 等标准工具。
- 破解功能仅可用于你自己拥有或已获授权的数据。

## 分支说明

- `master`：保留的 2014 旧版（MFC）。
- `rebuild-v2`：本次纯 Python 重写。
