# SecureBox CLI

无需 Python 的跨平台命令行工具。支持 Windows x64、macOS Apple Silicon 和 macOS Intel。

所有未指定 `-out` 的结果默认保存到 Downloads；分片默认每片 35 MB。加密采用 AES-256-GCM，密钥通过 PBKDF2-SHA256（390,000 次）从密码派生。

## 命令

```bash
# 加密 / 解密。密码可改用环境变量 SECUREBOX_PASSWORD。
securebox encrypt report.pdf -password "your-password"
securebox decrypt report.pdf.sbox -password "your-password"

# Base64
securebox encode input.bin
securebox decode input.bin.b64

# ZIP
securebox zip folder
securebox unzip folder.zip

# 默认 35 MB 分片。请同时发送生成的 .parts.json 清单。
securebox split large-file.zip
securebox join large-file.zip.part001
```

可选输出路径示例：

```bash
securebox encrypt report.pdf -out /tmp/report.sbox -password "your-password"
```

## 编译

要求 Go 1.24 或更高版本。在 macOS 或 Linux 上执行：

```bash
chmod +x build_all.sh
./build_all.sh
```

产物会写入 `release/`，包括 Windows x64、macOS arm64 与 macOS amd64 二进制文件。
