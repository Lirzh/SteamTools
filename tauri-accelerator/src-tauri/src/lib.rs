pub mod cert;
pub mod proxy;

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use cert::CertManager;
use proxy::{Proxy, ProxyConfig};
use serde::{Deserialize, Serialize};
use tauri::{Manager, WindowEvent};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub type CmdResult<T> = std::result::Result<T, String>;

// ---- 内存环形日志缓冲（供前端轮询展示） ----
static LOG_BUFFER: OnceLock<Mutex<VecDeque<String>>> = OnceLock::new();

fn log_buffer() -> &'static Mutex<VecDeque<String>> {
    LOG_BUFFER.get_or_init(|| Mutex::new(VecDeque::new()))
}

static LOGGER: BufLogger = BufLogger;

struct BufLogger;

impl log::Log for BufLogger {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }
    fn log(&self, record: &log::Record) {
        let line = format!("[{}] {}", record.level(), record.args());
        eprintln!("{line}");
        let mut buf = log_buffer().lock().unwrap();
        buf.push_back(line);
        while buf.len() > 500 {
            buf.pop_front();
        }
    }
    fn flush(&self) {}
}

fn init_logger() {
    let _ = log::set_logger(&LOGGER);
    log::set_max_level(log::LevelFilter::Info);
}
// ----

/// 固定监听端口。
const DEFAULT_PORT: u16 = 26561;

/// 持久化配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AppConfig {
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
            "github.com".into(),
            "api.github.com".into(),
            "githubusercontent.com".into(),
            "githubassets.com".into(),
            "raw.githubusercontent.com".into(),
            "codeload.github.com".into(),
            "avatars.githubusercontent.com".into(),
            "objects.githubusercontent.com".into(),
            "github-cloud.s3.amazonaws.com".into(),
            "cam.githubusercontent.com".into(),
        ];
        AppConfig {
            hosts,
            routes: HashMap::new(),
        }
    }
}

/// 运行中的代理句柄。
struct ProxyHandle {
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

/// 导出根 CA 到可执行文件所在目录，返回完整路径。
#[tauri::command]
async fn export_ca(
    app: tauri::AppHandle,
    state: tauri::State<'_, std::sync::Arc<AppState>>,
) -> CmdResult<String> {
    let pem = state.ca.ca_pem();
    // 优先取可执行文件所在目录
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .or_else(|| std::env::current_dir().ok());
    let dir = exe_dir.ok_or_else(|| "无法定位可执行文件目录".to_string())?;
    std::fs::create_dir_all(&dir).map_err(cmd_err)?;
    let path = dir.join("root-ca.pem");
    std::fs::write(&path, pem).map_err(cmd_err)?;
    log::info!("根证书已导出到 {}", path.display());
    let _ = app; // (预留)
    Ok(path.display().to_string())
}

/// 把根 CA 安装到系统信任库（Linux 下用 pkexec 提权）。
#[tauri::command]
async fn install_ca(
    app: tauri::AppHandle,
    state: tauri::State<'_, std::sync::Arc<AppState>>,
) -> CmdResult<String> {
    let pem = state.ca.ca_pem();
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .or_else(|| std::env::current_dir().ok())
        .ok_or_else(|| "无法定位可执行文件目录".to_string())?;
    let cert_path = exe_dir.join("root-ca.pem");
    std::fs::write(&cert_path, pem).map_err(cmd_err)?;

    let script = format!(
        "install -m 0644 '{}' /usr/local/share/ca-certificates/steam-accelerator-root-ca.crt && update-ca-certificates 2>/dev/null",
        cert_path.display()
    );
    let status = std::process::Command::new("pkexec")
        .args(["sh", "-c", &script])
        .status()
        .map_err(cmd_err)?;
    let _ = app;
    if status.success() {
        Ok("根证书已安装到系统信任库".to_string())
    } else {
        Err("安装未完成(可能已被取消或无权限)".to_string())
    }
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
            port: DEFAULT_PORT,
            hosts: cfg.hosts.iter().cloned().collect::<HashSet<_>>(),
            routes: cfg.routes.clone(),
        };
        let proxy: Arc<Proxy> = Arc::new(Proxy::new(proxy_cfg, Arc::clone(&state.ca)));
        let running = Arc::clone(&proxy);
        let task = tauri::async_runtime::spawn(async move {
            log::info!("代理已启动，监听 127.0.0.1:{DEFAULT_PORT}");
            if let Err(e) = running.run().await {
                log::error!("代理异常退出: {e}");
            }
        });
        *guard = Some(ProxyHandle { task });
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
        log::info!("代理已停止");
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
        port: DEFAULT_PORT,
        hosts: cfg.hosts.clone(),
    })
}

/// 返回最近日志（供前端展示）。
#[tauri::command]
fn get_logs() -> Vec<String> {
    log_buffer().lock().unwrap().iter().cloned().collect()
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

fn cmd_err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

impl AppState {
    fn load_config(data_dir: &PathBuf) -> AppConfig {
        let path = data_dir.join("config.json");
        let mut c = match std::fs::read_to_string(&path).ok().map(|s| {
            serde_json::from_str::<AppConfig>(&s).unwrap_or_default()
        }) {
            Some(c) => c,
            None => {
                let c = AppConfig::default();
                save_config(data_dir, &c);
                c
            }
        };
        // 合并默认域名清单，保证新增默认域名(如 github)在旧配置中也能出现
        for h in AppConfig::default().hosts {
            if !c.hosts.contains(&h) {
                c.hosts.push(h);
            }
        }
        c
    }
}

fn save_config(data_dir: &PathBuf, cfg: &AppConfig) {
    if let Ok(s) = serde_json::to_string_pretty(cfg) {
        let _ = std::fs::create_dir_all(data_dir);
        let _ = std::fs::write(data_dir.join("config.json"), s);
    }
}

/// 系统托盘库是否可用（Linux：libayatana-appindicator3 / libappindicator3）。
fn appindicator_available() -> bool {
    std::process::Command::new("ldconfig")
        .arg("-p")
        .output()
        .map(|o| {
            let s = String::from_utf8_lossy(&o.stdout).to_lowercase();
            s.contains("libayatana-appindicator3") || s.contains("libappindicator3")
        })
        .unwrap_or(false)
}

/// 尽力创建托盘；缺库返回 None（此时关闭窗口仅隐藏，不崩溃）。
fn build_tray(app: &tauri::App) -> tauri::Result<()> {
    if !appindicator_available() {
        log::warn!("未检测到系统托盘库，关闭窗口后仅隐藏，后台持续运行");
        return Ok(());
    }
    let Some(icon) = app.default_window_icon().cloned() else {
        log::warn!("无默认图标，跳过托盘");
        return Ok(());
    };
    let quit_i = tauri::menu::MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
    let show_i =
        tauri::menu::MenuItem::with_id(app, "show", "显示主窗口", true, None::<&str>)?;
    let menu = tauri::menu::Menu::with_items(app, &[&show_i, &quit_i])?;
    tauri::tray::TrayIconBuilder::new()
        .icon(icon)
        .tooltip("Steam++ 网络加速")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => {
                if let Some(w) = app.get_webview_window("main") {
                    w.show().ok();
                    w.set_focus().ok();
                }
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .build(app)?;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    init_logger();
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
            log::info!("应用初始化完成");

            // 托盘：关闭窗口后转入后台（缺系统托盘库时跳过，仅隐藏窗口）
            if let Some(app) = build_tray(app) {
                let _ = app;
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // 关闭窗口时隐藏到托盘，保持代理后台运行
            if let WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .invoke_handler(tauri::generate_handler![
            export_ca,
            install_ca,
            start_proxy,
            stop_proxy,
            status,
            set_hosts,
            get_logs
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}