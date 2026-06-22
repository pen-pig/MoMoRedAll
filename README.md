# MomoRedAll

让 Momo / DuckDector 全部检测项报红的 LSPosed 模块。

## 编译

```bash
chmod +x build.sh && ./build.sh
```

需要 Linux 容器（curl, unzip, tar），约 2G 空闲空间。build.sh 会自动下载 JDK 17 和 Android SDK。

## 文件说明

| 文件 | 说明 |
|------|------|
| `build.sh` | 一键编译脚本 |
| `MomoRedAll.kt` | 核心 Hook 代码 |

## 模块作用域

- Momo: `io.github.vvb2060.mahoshojo`
- KeyAttestation: `io.github.vvb2060.keyattestation`
- DuckDector: `duckduckgo.mobile.android`
