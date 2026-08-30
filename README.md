<h1 align="center">Steam++ 网络加速（Tauri 版）</h1>

<div align="center">

[English](./README.en.md) | 简体中文

基于 **Tauri**（Rust + Web）重写的轻量网络加速工具，仅保留网络加速核心功能。

</div>

## 功能

- **HTTPS 网络加速**：本地代理监听 `127.0.0.1:26561`，对勾选的加速域名做 MITM 解密转发，其余域名透明直连。
- **加速域名清单**：内置 Steam / GitHub 等常用域名，可勾选启用。
- **根证书管理**：自动生成根 CA，可导出或一键安装到系统信任库。
- **网络连通测试**：对勾选域名批量测速，逐域名标注延迟。
- **实时流量监控**：上传/下载速率 + 近 60 秒实时折线图。
- **详细日志**：连接、转发、字节数等均可查看。
- **后台运行**：关闭窗口转系统托盘，代理持续运行。

## 构建

依赖 Linux 桌面构建库（webkit2gtk-4.1 / gtk3 / libsoup3 等）与 Rust 工具链：

```bash
cd tauri-accelerator/src-tauri
cargo build --release
```

产物位于 `src-tauri/target/release/steam-accelerator`。

## 运行

```bash
./steam-accelerator
```

- 系统代理指向 `127.0.0.1:26561` 后，勾选域名并点击「开始加速」即可加速。
- 建议先「安装到系统」信任根证书，HTTPS 加速才生效。

## 目录结构

- `tauri-accelerator/dist/`：前端界面（纯 HTML/JS，无框架）
- `tauri-accelerator/src-tauri/src/`：Rust 后端（代理 / 证书 / Tauri 命令）

## 许可

[GPL-3.0](./LICENSE)