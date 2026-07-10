//! Local web dashboard: serves the SPA in `web/` and pushes live stats
//! over a WebSocket. Bound to loopback by default -- this is a
//! single-machine control panel, not a remote API.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use serde::Serialize;
use tokio::sync::RwLock;
use tower_http::services::ServeDir;

/// Snapshot of daemon state the dashboard cares about. Populated by the
/// transport loop as it runs; the fields here mirror the security panel
/// and status page directly so there's no reshaping needed on the wire.
#[derive(Clone)]
pub struct DashboardState {
    pub connected: bool,
    pub peer_name: String,
    pub session_start: Instant,
    pub ratchet_epoch: u64,
    pub packets_since_rekey: u32,
    pub rekey_packet_threshold: u32,
    pub last_rekey: Instant,
    pub tx_bytes_per_sec: f64,
    pub rx_bytes_per_sec: f64,
    pub obfuscation_enabled: bool,
    pub padding_enabled: bool,
    pub cover_traffic_enabled: bool,
}

impl Default for DashboardState {
    fn default() -> Self {
        let now = Instant::now();
        DashboardState {
            connected: false,
            peer_name: String::new(),
            session_start: now,
            ratchet_epoch: 0,
            packets_since_rekey: 0,
            rekey_packet_threshold: crate::crypto::dh_ratchet::DEFAULT_REKEY_PACKET_THRESHOLD,
            last_rekey: now,
            tx_bytes_per_sec: 0.0,
            rx_bytes_per_sec: 0.0,
            obfuscation_enabled: true,
            padding_enabled: true,
            cover_traffic_enabled: false,
        }
    }
}

#[derive(Serialize)]
struct StatsPayload {
    connected: bool,
    peer_name: String,
    uptime_secs: f64,
    ratchet_epoch: u64,
    packets_since_rekey: u32,
    rekey_packet_threshold: u32,
    secs_since_rekey: f64,
    tx_bytes_per_sec: f64,
    rx_bytes_per_sec: f64,
    obfuscation_enabled: bool,
    padding_enabled: bool,
    cover_traffic_enabled: bool,
}

impl From<&DashboardState> for StatsPayload {
    fn from(s: &DashboardState) -> Self {
        StatsPayload {
            connected: s.connected,
            peer_name: s.peer_name.clone(),
            uptime_secs: s.session_start.elapsed().as_secs_f64(),
            ratchet_epoch: s.ratchet_epoch,
            packets_since_rekey: s.packets_since_rekey,
            rekey_packet_threshold: s.rekey_packet_threshold,
            secs_since_rekey: s.last_rekey.elapsed().as_secs_f64(),
            tx_bytes_per_sec: s.tx_bytes_per_sec,
            rx_bytes_per_sec: s.rx_bytes_per_sec,
            obfuscation_enabled: s.obfuscation_enabled,
            padding_enabled: s.padding_enabled,
            cover_traffic_enabled: s.cover_traffic_enabled,
        }
    }
}

pub type SharedDashboardState = Arc<RwLock<DashboardState>>;

pub fn router(state: SharedDashboardState, static_dir: PathBuf) -> Router {
    Router::new()
        .route("/api/stats", get(stats_ws))
        .fallback_service(ServeDir::new(static_dir))
        .with_state(state)
}

async fn stats_ws(ws: WebSocketUpgrade, State(state): State<SharedDashboardState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| stream_stats(socket, state))
}

async fn stream_stats(mut socket: WebSocket, state: SharedDashboardState) {
    let mut interval = tokio::time::interval(Duration::from_millis(1000));
    loop {
        interval.tick().await;
        let payload = {
            let guard = state.read().await;
            StatsPayload::from(&*guard)
        };
        let json = match serde_json::to_string(&payload) {
            Ok(j) => j,
            Err(_) => continue,
        };
        if socket.send(Message::Text(json.into())).await.is_err() {
            break;
        }
    }
}
