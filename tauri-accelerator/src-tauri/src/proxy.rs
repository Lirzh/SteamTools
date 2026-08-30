use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http2::{handshake as http2_handshake, SendRequest};
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex as AsyncMutex;

use crate::cert::CertManager;

/// 实时流量计数（上传/下载字节）。
#[derive(Debug, Default)]
pub struct ProxyStats {
    pub up: AtomicU64,
    pub down: AtomicU64,
}

impl ProxyStats {
    /// 返回 (上传, 下载) 字节。
    pub fn total(&self) -> (u64, u64) {
        (
            self.up.load(Ordering::Relaxed),
            self.down.load(Ordering::Relaxed),
        )
    }
}

/// 加速配置。
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub port: u16,
    /// 需要被 MITM 拦截的加速主机名集合（小写、不含端口）。
    pub hosts: HashSet<String>,
    /// host -> 上游替代地址 "host:port"（把连接导向优化后的加速节点）。
    pub routes: HashMap<String, String>,
}

pub struct Proxy {
    cfg: ProxyConfig,
    ca: Arc<CertManager>,
    stats: Arc<ProxyStats>,
    pool: Arc<UpstreamPool>,
}

impl Proxy {
    pub fn new(cfg: ProxyConfig, ca: Arc<CertManager>, stats: Arc<ProxyStats>) -> Self {
        Proxy {
            cfg,
            ca,
            stats,
            pool: Arc::new(UpstreamPool::new()),
        }
    }

    fn canonical_host(authority: &str) -> String {
        let host = authority.split(':').next().unwrap_or(authority);
        host.trim_end_matches('.').to_lowercase()
    }

    fn upstream_for(&self, host: &str, default_port: u16) -> (String, u16) {
        if let Some(route) = self.cfg.routes.get(host) {
            let (h, p) = split_host_port(route, default_port);
            return (h, p.unwrap_or(default_port));
        }
        (host.to_string(), default_port)
    }

    /// 是否为加速域名（精确匹配，或子域匹配：`github.githubassets.com` 命中 `githubassets.com`）。
    fn is_accel_host(&self, host: &str) -> bool {
        self.cfg.hosts.iter().any(|base| {
            host == base || {
                host.len() > base.len()
                    && host.ends_with(base)
                    && host.as_bytes()[host.len() - base.len() - 1] == b'.'
            }
        })
    }

    /// 启动监听（HTTP 代理，用于流量的 MITM/透传）。
    pub async fn run(self: Arc<Self>) -> crate::Result<()> {
        let listener = TcpListener::bind(("127.0.0.1", self.cfg.port)).await?;
        log::info!("代理正在监听 127.0.0.1:{}", self.cfg.port);
        loop {
            let (stream, peer) = listener.accept().await?;
            let peer_s = peer.to_string();
            let proxy = Arc::clone(&self);
            tokio::spawn(async move {
                log::info!("连接来自 {peer_s}");
                if let Err(e) = proxy.handle_stream(stream).await {
                    match is_benign(e.as_ref()) {
                        true => log::debug!("连接结束(正常中断, 对端 {peer_s}): {e}"),
                        false => log::warn!("代理流错误(对端 {peer_s}): {e}"),
                    }
                }
            });
        }
    }

    /// 处理单条客户端连接。
    ///
    /// 读取请求头（到 `\r\n\r\n`）后，按方法分流：
    /// - `CONNECT`：回复 200 后进入隧道（加速域名 MITM，其余透传）。
    /// - 其它方法：把请求盲转发起上方节点，随后双向转发。
    async fn handle_stream(&self, mut stream: TcpStream) -> crate::Result<()> {
        let head = read_head(&mut stream).await?;
        if head.starts_with(b"CONNECT") {
            return self.handle_connect(stream, &head).await;
        }
        self.handle_plain(stream, &head).await
    }

    /// CONNECT：先回 200 建立隧道，再按域名决定 MITM 还是纯透传。
    async fn handle_connect(&self, stream: TcpStream, head: &[u8]) -> crate::Result<()> {
        let first = head
            .split(|&b| b == b'\n')
            .next()
            .unwrap_or(b"");
        let first = String::from_utf8_lossy(first);
        let target = first.split_whitespace().nth(1).unwrap_or("").to_string();

        let (host, port) = split_host_port(&target, 443);
        let port = port.unwrap_or(443);

        // 先回 200，隧道建立后再开始转发
        let mut stream = stream;
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        let host = Self::canonical_host(&host);
        if self.is_accel_host(&host) {
            log::info!("[HTTPS] {host}:{port} → MITM 加速");
            self.proxy_mitm(stream, host).await
        } else {
            log::info!("[HTTPS] {host}:{port} → 透传");
            let (up_ip, up_port) = self.upstream_for(&host, port);
            let upstream = TcpStream::connect((up_ip.as_str(), up_port)).await?;
            relay(stream, upstream, Arc::clone(&self.stats)).await
        }
    }

    /// 普通请求：把请求头改写为 origin-form 后原样转发，其余字节双向透传。
    async fn handle_plain(&self, stream: TcpStream, head: &[u8]) -> crate::Result<()> {
        let head_str = String::from_utf8_lossy(head);
        let mut lines = head_str.split("\r\n");
        let request_line = lines.next().unwrap_or("");
        let mut rp = request_line.split_whitespace();
        let method = rp.next().unwrap_or("GET").to_string();
        let target = rp.next().unwrap_or("/").to_string();
        let version = rp.next().unwrap_or("HTTP/1.1").to_string();

        let authority = absolute_target_authority(&target)
            .or_else(|| host_from_header(lines.clone()));
        let (host, port) = match authority {
            Some((h, p)) => (h, p),
            None => return Ok(()), // 无法确定上游，直接关闭
        };
        let hostname = Self::canonical_host(&host);
        let default_port = if target.starts_with("https://") { 443 } else { 80 };
        let p = port.unwrap_or(default_port);
        let (up_ip, up_port) = self.upstream_for(&hostname, p);
        log::info!("[HTTP] {method} {hostname} → {up_ip}:{up_port}");

        let mut upstream = TcpStream::connect((up_ip.as_str(), up_port)).await?;

        // 若目标为绝对形式，把请求行改写为 origin-form，并重新写 Host
        let new_request_line = if absolute_target_authority(&target).is_some() {
            let path = absolute_path(&target);
            format!("{method} {path} {version}")
        } else {
            request_line.to_string()
        };
        let mut out: Vec<u8> = Vec::with_capacity(head.len() + 16);
        out.extend_from_slice(new_request_line.as_bytes());
        // 追加原始请求行的后续（其余以 \r\n 开头）
        let body_start = head_str.find("\r\n").map(|i| i + 2).unwrap_or(head.len());
        out.extend_from_slice(&head[body_start..]);
        upstream.write_all(&out).await?;

        relay(stream, upstream, Arc::clone(&self.stats)).await
    }

    /// HTTPS MITM：用本地根 CA 向客户端动态签发叶子证书；
    /// 后续客户端 HTTP/1.1 请求通过「同主机共享的 HTTP/2 上游连接」复用转发。
    async fn proxy_mitm(&self, stream: TcpStream, host: String) -> crate::Result<()> {
        // 客户端侧 TLS 服务端：按 SNI 动态签发叶子证书
        let resolver = self.ca.resolver();
        let server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
        let client_stream = acceptor.accept(stream).await?;

        let pool = Arc::clone(&self.pool);
        let service = hyper::service::service_fn(move |req: Request<Incoming>| {
            let pool = Arc::clone(&pool);
            let host = host.clone();
            async move { Ok::<_, Box<dyn std::error::Error + Send + Sync>>(handle_upstream(pool, &host, req).await?) }
        });
        let conn = hyper::server::conn::http1::Builder::new()
            .serve_connection(Box::pin(TokioIo::new(client_stream)), service)
            .with_upgrades();
        let _ = conn.await;
        Ok(())
    }
}

/// 按 host 共享单一 HTTP/2 上游连接的连接池。
struct UpstreamPool {
    inner: AsyncMutex<HashMap<String, SendRequest<Full<Bytes>>>>,
}

impl UpstreamPool {
    fn new() -> Self {
        Self {
            inner: AsyncMutex::new(HashMap::new()),
        }
    }

    /// 把请求发往该主机的共享 HTTP/2 连接；首次访问时建立连接。
    ///
    /// 关键点：给「同主机」的多个请求复用同一条 HTTP/2 连接，并真正并行
    /// 多路复用——锁内只 `clone` 出发送端后立即释放锁，避免串行排队。
    /// 若发送端已失效（上游断开），移除坏连接并重建后重试一次。
    async fn send(
        &self,
        host: &str,
        req: Request<Full<Bytes>>,
    ) -> crate::Result<Response<Incoming>> {
        // clone 出便宜的多路复用发送端（body 为 Arc<Bytes>，浅拷贝）。
        // 发送端拿到后锁即释放，允许同主机多个请求在 Y 一条连接上真正并行。
        let mut sender = self.sender(host).await?;
        match sender.send_request(req.clone()).await {
            Ok(res) => Ok(res),
            Err(_) => {
                // 连接可能已陈旧/被上游关闭：移除坏连接，重建后重试一次。
                self.dispose(host).await;
                let sender = self.sender(host).await?;
                Ok(sender.send_request(req).await?)
            }
        }
    }

    /// 在锁内取出（或首次建立）该主机的 HTTP/2 发送端后立即释放锁。
    async fn sender(&self, host: &str) -> crate::Result<SendRequest<Full<Bytes>>> {
        let mut guard = self.inner.lock().await;
        if let Some(s) = guard.get(host) {
            return Ok(s.clone());
        }
        let s = establish_http2(host).await?;
        guard.insert(host.to_string(), s.clone());
        log::info!("[上游] 已建立 {host} 的共享 HTTP/2 连接");
        Ok(s)
    }

    async fn dispose(&self, host: &str) {
        let mut guard = self.inner.lock().await;
        guard.remove(host);
    }
}

/// 建一条到 host:443 的 HTTP/2 上游连接（TLS 不校验 + ALPN h2）。
async fn establish_http2(host: &str) -> crate::Result<SendRequest<Full<Bytes>>> {
    let mut addrs = tokio::net::lookup_host((host, 443)).await?;
    let ip = addrs
        .next()
        .ok_or_else(|| std::io::Error::other("dns no result"))?;
    let tcp = TcpStream::connect(ip).await?;
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| std::io::Error::other("bad host"))?;
    let mut cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NullVerifier))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let tls = connector.connect(server_name, tcp).await?;
    let (sender, connection) =
        http2_handshake(TokioExecutor::new(), Box::pin(TokioIo::new(tls))).await?;
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            log::debug!("上游 http2 连接结束: {e}");
        }
    });
    Ok(sender)
}

/// 把客户端的一个 HTTP 请求（已 MITM 解密）转送到共享上游，并回读响应。
async fn handle_upstream(
    pool: Arc<UpstreamPool>,
    host: &str,
    req: Request<Incoming>,
) -> crate::Result<Response<Full<Bytes>>> {
    let (parts, body) = req.into_parts();
    let body_bytes = body.collect().await?;
    let path = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let uri = format!("https://{host}{path}");

    let mut ureq = Request::builder()
        .method(parts.method.clone())
        .uri(uri)
        .version(hyper::Version::HTTP_2)
        .header(hyper::header::HOST, host)
        .body(Full::from(body_bytes))?;
    for (name, value) in &parts.headers {
        let low = name.as_str().to_ascii_lowercase();
        let hop = matches!(
            low.as_str(),
            "host"
                | "connection"
                | "keep-alive"
                | "proxy-connection"
                | "transfer-encoding"
                | "upgrade"
                | "proxy-authorization"
                | "te"
                | "trailer"
        );
        if hop {
            continue;
        }
        ureq.headers_mut().insert(name.clone(), value.clone());
    }

    let res = pool.send(host, ureq).await?;
    let (rparts, rbody) = res.into_parts();
    let rbytes = rbody.collect().await?;
    Ok(Response::from_parts(rparts, Full::from(rbytes)))
}

/// 双向转发两个连接，并累计上传/下载字节到 stats。
/// 方向约定：a=客户端，b=上游；a→b 记为上传，b→a 记为下载。
async fn relay<A, B>(a: A, b: B, stats: Arc<ProxyStats>) -> crate::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);
    let up_before = stats.up.load(Ordering::Relaxed);
    let down_before = stats.down.load(Ordering::Relaxed);
    let up_stats = Arc::clone(&stats);
    let up = tokio::spawn(async move {
        let n = tokio::io::copy(&mut ar, &mut bw).await.unwrap_or(0);
        up_stats.up.fetch_add(n, Ordering::Relaxed);
    });
    let down_stats = Arc::clone(&stats);
    let down = tokio::spawn(async move {
        let n = tokio::io::copy(&mut br, &mut aw).await.unwrap_or(0);
        down_stats.down.fetch_add(n, Ordering::Relaxed);
    });
    let _ = up.await;
    let _ = down.await;
    let up = stats.up.load(Ordering::Relaxed) - up_before;
    let down = stats.down.load(Ordering::Relaxed) - down_before;
    if up > 0 || down > 0 {
        log::info!("转发完成: 上传 {up} 字节, 下载 {down} 字节");
    }
    Ok(())
}

/// 是否是连接中断类的良性错误（对端提前关闭/重置/超时），无需打印刷屏。
fn is_benign(e: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
    if let Some(io) = e.downcast_ref::<std::io::Error>() {
        matches!(
            io.kind(),
            std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::NotConnected
                | std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::WriteZero
        )
    } else {
        false
    }
}

/// 读取网络数据直到遇到 `\r\n\r\n`（请求头结尾），返回读出内容。
async fn read_head(stream: &mut TcpStream) -> crate::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if find_subslice(&buf, b"\r\n\r\n") {
            break;
        }
        if buf.len() > 65536 {
            return Err(std::io::Error::other("headers too large").into());
        }
    }
    Ok(buf)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle)
}

/// 解析绝对形式的请求目标中的 authority：`http://host:port/path`。
fn absolute_target_authority(target: &str) -> Option<(String, Option<u16>)> {
    let without_scheme = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))?;
    let authority = without_scheme.split(['/', '?', '#']).next()?;
    let (host, port) = split_host_port(authority, 0);
    match port {
        Some(0) | None => Some((host, None)),
        Some(p) => Some((host, Some(p))),
    }
}

/// 从 Host 头解析 authority。
fn host_from_header<'a>(lines: impl Iterator<Item = &'a str>) -> Option<(String, Option<u16>)> {
    for line in lines {
        if let Some(v) = line.to_ascii_lowercase().strip_prefix("host:") {
            let v = v.trim();
            return Some(match split_host_port(v, 0) {
                (h, Some(p)) if p != 0 => (h, Some(p)),
                _ => (v.to_string(), None),
            });
        }
    }
    None
}

/// 解析 `host[:port]`，返回 (host, port)。
fn split_host_port(s: &str, default_port: u16) -> (String, Option<u16>) {
    if let Some((h, p)) = s.rsplit_once(':') {
        if let Ok(p) = p.parse::<u16>() {
            return (h.to_string(), Some(p));
        }
    }
    let _ = default_port;
    (s.to_string(), None)
}

/// 从绝对 URI 提取路径（含 query），缺省为 `/`。
fn absolute_path(target: &str) -> String {
    let rest = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
        .unwrap_or(target);
    match rest.find('/') {
        Some(i) => rest[i..].to_string(),
        None => "/".to_string(),
    }
}

/// 不做上游证书校验（MITM 透明重加密）。
#[derive(Debug)]
pub struct NullVerifier;

impl rustls::client::danger::ServerCertVerifier for NullVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer,
        _intermediates: &[rustls::pki_types::CertificateDer],
        _server_name: &rustls::pki_types::ServerName,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
        ]
    }
}