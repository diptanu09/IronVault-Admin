//! All Slint callback registrations, grouped by feature area. Each module
//! exposes a single `register(app, ctx)` function that wires its callbacks
//! into the given AppWindow.

pub mod audit_log;
pub mod auth;
pub mod gpffp;
pub mod pendak;
pub mod pension;
pub mod step_up;
pub mod users;

use crate::context::SharedContext;
use crate::AppWindow;

/// Wires every handler module's callbacks into the given window.
/// Called once from `main()` after the window and context are constructed.
pub fn register_all(app: &AppWindow, ctx: SharedContext) {
    auth::register(app, ctx.clone());
    users::register(app, ctx.clone());
    audit_log::register(app, ctx.clone());
    gpffp::register(app, ctx.clone());
    pendak::register(app, ctx.clone());
    pension::register(app, ctx.clone());
    step_up::register(app, ctx);
}
