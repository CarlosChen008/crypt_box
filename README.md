# crypt_box · 密码学工具箱

一个本科时期的密码学课程项目，现已重写。

- **旧版**（`crypt_box/` 目录）：2014 年用 MFC / VC++ 编写的启动器，本身通过
  `ShellExecute` 调用 `tools/` 下若干编译好的 exe（MD5、SHA1、DES、Hill、RSA 等），
  源码已缺失，仅作历史保留。
- **新版**（`cryptobox/` 目录，本 README 所介绍）：使用**纯 Python** 重写，
  **所有密码算法均为手写实现**，不依赖 `hashlib` / `cryptography` /
  `pycryptodome` 等任何现成加密库，便于学习与研究。GUI 采用标准库自带的
  Tkinter，Windows / macOS / Linux 均可运行。

## 功能

| 分组 | 功能 |
| --- | --- |
| 摘要计算 | MD5、SHA1、SHA256；支持文本与文件，输出 hex |
| 摘要破解 | 字典攻击（内置常用密码表 / 自选字典）、暴力破解；支持加盐 |
| 对称加密 | AES-256（CTR + HMAC，推荐）、AES-256 CBC、DES / 3DES（教学）、Hill 密码 |
| 公钥加密 | RSA 生成密钥、加密 / 解密（OAEP-SHA256 或 PKCS#1 v1.5）、签名 / 验证 |

## 手写算法清单

- MD5（RFC 1321）
- SHA1（FIPS 180-1）、SHA256（FIPS 180-4）
- HMAC-SHA256（RFC 2104）、PBKDF2-HMAC-SHA256（RFC 8018）
- DES / Triple-DES（FIPS 46-3，CBC）
- AES-128/192/256（FIPS 197，CBC / CTR）
- Hill 密码（模 26 矩阵）
- RSA（Miller-Rabin 素性测试、模幂、OAEP、PKCS#1 v1.5、签名）

仅 Base64 / Hex 编码使用 Python 标准库，用于数据表示。

## 快速开始

需要 Python 3.8+（推荐 3.10+）。

```bash
cd cryptobox

# 图形界面
python run_gui.py          # 或 Windows 下双击 run_gui.bat

# 命令行
python run_cli.py hash MD5 abc
python run_cli.py crack MD5 5f4dcc3b5aa765d61d8327deb882cf99
python run_cli.py encrypt aes "passphrase" "hello"
python run_cli.py rsa-gen 2048 > key.txt
```

Linux 若缺少 Tkinter：`sudo apt install python3-tk`。Windows / macOS 官方
Python 自带 Tkinter，无需额外安装。

## 目录结构

```
cryptobox/
├── run_gui.py / run_gui.bat   # 图形界面入口
├── run_cli.py                 # 命令行入口
├── cryptobox/
│   ├── core/                  # 手写密码算法
│   ├── crack/                 # 字典 / 暴力破解
│   ├── gui/                   # Tkinter 界面
│   └── data/                  # 内置常用密码表
├── tests/                     # 单元测试（标准测试向量）
└── build/                     # PyInstaller 打包脚本
```

## 测试

```bash
cd cryptobox
python -m unittest discover -s tests -t . -v
```

覆盖 MD5 / SHA1 / SHA256 / HMAC / PBKDF2 / DES / AES / Hill / RSA 的标准向量
与加解密往返。

## 打包为单文件可执行程序

需要额外安装 PyInstaller（仅打包用，运行不需要）：`python -m pip install pyinstaller`。

- Windows：`build\build_windows.bat` → `dist\Cryptobox.exe`
- Linux：`bash build/build_linux.sh`
- macOS：`bash build/build_macos.sh`

## 安全说明（重要）

本项目是**教学 / 研究**工具，部分算法与参数为演示目的而选择，请勿用于生产：

- MD5、SHA1、DES、3DES 已不安全，仅用于学习经典算法。
- AES 推荐 CTR + HMAC-SHA256（先加密后认证）；CBC 模式不含认证。
- PBKDF2 迭代次数为 4096（纯 Python 较慢），生产环境应更高或改用 Argon2。
- RSA 密钥建议 2048 位以上；OAEP-SHA256 需要密钥至少 528 位。
- 密钥采用自定义 PEM 风格文本格式，**不兼容** OpenSSL 等标准工具。
- 破解功能仅可用于你拥有或已获授权的数据。

## 分支说明

- `master`：保留的 2014 旧版（MFC）。
- `rebuild-v2`：纯 Python 重写版本。

更完整的新版说明见 [`cryptobox/README.md`](cryptobox/README.md)。
