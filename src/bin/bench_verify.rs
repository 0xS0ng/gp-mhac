//! Measure external verification versus attribute count.
#[path = "support/local.rs"]
pub mod local;
#[path = "support/mhac_cost.rs"]
pub mod mhac_cost;
fn main() {
    local::run("verify");
}
