pub mod cert;
pub mod proxy;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use cert::CertManager;
use proxy::{Proxy, ProxyConfig};
use serde::{Deserialize, Serialize};
use tauri::Manager;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub type CmdResult<T> = std::result::Result<T, String>;

/// 持久化配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AppConfig {
    port: u16,
    hosts: Vec<String>,
    routes: HashMap<String, String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        let hosts = vec![
            "store.steampowered.com".into(),
            "steampowered.com".into(),
            "steamcommunity.com".into(),
            "api.steampowered.com".into(),
            "steamstatic.com".into(),
            "cdn.cloudflare.steamstatic.com".into(),
            "client-update.akamai.steamstatic.com".into(),
            "community.akamai.steamstatic.com".into(),
            "edge.steamstatic.com".into(),
            "steam-chat.com".into(),
            "steamusercontent.com".into(),
            "steamusercontent-a.akamaihd.net".into(),
        ];
        AppConfig {
            port: 26561,
            hosts,
            routes: HashMap::new(),
        }
    }
}

/// 运行中的代理句柄。
struct ProxyHandle {
    port: u16,
    task: tauri::async_runtime::JoinHandle<()>,
}

/// 应用状态。
pub struct AppState {
    ca: std::sync::Arc<CertManager>,
    data_dir: PathBuf,
    config: Mutex<AppConfig>,
    proxy: Mutex<Option<ProxyHandle>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Status {
    running: bool,
    port: u16,
    hosts: Vec<String>,
}

/// 导出根 CA 到 data 目录，返回文件名（用于系统信任库安装）。
#[tauri::command]
async fn export_ca(state: tauri::State<'_, std::sync::Arc<AppState>>) -> CmdResult<String> {
    let pem = state.ca.ca_pem();
    let path = state.data_dir.join("root-ca.pem");
    std::fs::write(&path, pem).map_err(cmd_err)?;
    Ok(path.display().to_string())
}

#[tauri::command]
async fn start_proxy(
    app: tauri::AppHandle,
    state: tauri::State<'_, std::sync::Arc<AppState>>,
) -> CmdResult<()> {
    {
        let mut guard = state.proxy.lock().unwrap();
        if guard.is_some() {
            return Err("代理已在运行".into());
        }
        let cfg = state.config.lock().unwrap().clone();
        let proxy_cfg = ProxyConfig {
            port: cfg.port,
            hosts: cfg.hosts.iter().cloned().collect::<HashSet<_>>(),
            routes: cfg.routes.clone(),
        };
        let proxy: Arc<Proxy> = Arc::new(Proxy::new(proxy_cfg, Arc::clone(&state.ca)));
        let running = Arc::clone(&proxy);
        let task = tauri::async_runtime::spawn(async move {
            if let Err(e) = running.run().await {
                eprintln!("proxy exited: {e}");
            }
        });
        *guard = Some(ProxyHandle { port: cfg.port, task });
    }
    let _ = app; // (预留：启动后可回调前端状态)
    Ok(())
}

#[tauri::command]
async fn stop_proxy(
    state: tauri::State<'_, std::sync::Arc<AppState>>,
) -> CmdResult<()> {
    let mut guard = state.proxy.lock().unwrap();
    if let Some(h) = guard.take() {
        h.task.abort();
    }
    Ok(())
}

#[tauri::command]
async fn status(
    state: tauri::State<'_, std::sync::Arc<AppState>>,
) -> CmdResult<Status> {
    let guard = state.proxy.lock().unwrap();
    let cfg = state.config.lock().unwrap().clone();
    Ok(Status {
        running: guard.is_some(),
        port: cfg.port,
        hosts: cfg.hosts.clone(),
    })
}

#[tauri::command]
async fn set_hosts(
    app: tauri::AppHandle,
    state: tauri::State<'_, std::sync::Arc<AppState>>,
    hosts: Vec<String>,
) -> CmdResult<()> {
    let mut cfg = state.config.lock().unwrap();
    cfg.hosts = hosts.iter().map(|s| normalize_host(s)).collect();
    let cfg = cfg.clone();
    save_config(&state.data_dir, &cfg);
    drop(cfg);
    // 若正在运行则重启以应用新清单
    if state.proxy.lock().unwrap().is_some() {
        let _ = app;
    }
    Ok(())
}

fn normalize_host(s: &str) -> String {
    s.split(':').next().unwrap_or(s).trim_end_matches('.').to_lowercase()
}

/// 设置监听端口并持久化。
#[tauri::command]
async fn set_port(
    state: tauri::State<'_, std::sync::Arc<AppState>>,
    port: u16,
) -> CmdResult<()> {
    let mut cfg = state.config.lock().unwrap();
    cfg.port = port;
    let cfg = cfg.clone();
    save_config(&state.data_dir, &cfg);
    Ok(())
}

fn cmd_err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

impl AppState {
    fn load_config(data_dir: &PathBuf) -> AppConfig {
        let path = data_dir.join("config.json");
        match std::fs::read_to_string(&path).ok().map(|s| {
            serde_json::from_str::<AppConfig>(&s).unwrap_or_default()
        }) {
            Some(c) => c,
            None => {
                let c = AppConfig::default();
                save_config(data_dir, &c);
                c
            }
        }
    }
}

fn save_config(data_dir: &PathBuf, cfg: &AppConfig) {
    if let Ok(s) = serde_json::to_string_pretty(cfg) {
        let _ = std::fs::create_dir_all(data_dir);
        let _ = std::fs::write(data_dir.join("config.json"), s);
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let data_dir = app
                .path()
                .app_data_dir()
                .unwrap_or_else(|_| PathBuf::from("."));
            std::fs::create_dir_all(&data_dir).ok();
            let ca = std::sync::Arc::new(
                CertManager::load_or_create(data_dir.join("certs")).map_err(cmd_err)?,
            );
            let cfg = AppState::load_config(&data_dir);
            let state = std::sync::Arc::new(AppState {
                ca,
                data_dir,
                config: Mutex::new(cfg),
                proxy: Mutex::new(None),
            });
            app.manage(state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            export_ca,
            start_proxy,
            stop_proxy,
            status,
            set_hosts,
            set_port
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}