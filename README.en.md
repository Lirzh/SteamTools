<h1 align="center">Steam++ Network Accelerator (Tauri)</h1>

<div align="center">

English | [简体中文](./README.md)

A lightweight network accelerator rewritten with **Tauri** (Rust + Web), focusing on the core network acceleration feature only.

</div>

## Features

- **HTTPS acceleration**: local proxy listens on `127.0.0.1:26561`, MITM-decrypts and forwards traffic for selected accelerator domains, transparently bypasses the rest.
- **Domain list**: built-in Steam / GitHub common domains, toggleable.
- **Root CA management**: auto-generated CA, exportable or installable into the system trust store.
- **Connectivity test**: batch latency test for selected domains, per-domain labeling.
- **Real-time traffic monitoring**: upload/download rates + live 60-second line chart.
- **Detailed logs**: connections, forwarding, byte counts.
- **Background running**: closing the window keeps the proxy running via the system tray.

## Build

Requires Linux desktop build libraries (webkit2gtk-4.1 / gtk3 / libsoup3) and the Rust toolchain:

```bash
cd tauri-accelerator/src-tauri
cargo build --release
```

The artifact is at `src-tauri/target/release/steam-accelerator`.

## Run

```bash
./steam-accelerator
```

- Point your system proxy at `127.0.0.1:26561`, select domains, and click "Start" to accelerate.
- It is recommended to "Install to System" to trust the root CA first, which is required for HTTPS acceleration.

## Layout

- `tauri-accelerator/dist/`: frontend UI (vanilla HTML/JS, no framework)
- `tauri-accelerator/src-tauri/src/`: Rust backend (proxy / cert / Tauri commands)

## License

[GPL-3.0](./LICENSE)