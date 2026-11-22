//! Measure paired local latency and emulated LAN/WAN latency with persistent holder processes.
#[path = "support/network.rs"]
pub mod network;
fn main() -> std::io::Result<()> {
    network::run()
}
