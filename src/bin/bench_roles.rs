//! Measure per-role presentation cost.
#[path = "support/local.rs"]
pub mod local;
#[path = "support/mhac_cost.rs"]
pub mod mhac_cost;
fn main() {
    local::run("roles");
}
