//! The control plane's integration tests, one module per area, linked into one binary. As a
//! binary each, they were thirteen copies of the same linked code, about 57 MB apiece, and
//! thirteen link steps.
//!
//! The modules share one process, so whatever state is global to it is shared between them too.
//! The database is the one that matters: every module's tests reset the same schema, so they all
//! take turns through `common::fresh_store`'s single lock, never one of their own. Run one module
//! with its path as the filter:
//!
//! ```text
//! GAPURA_TEST_DATABASE_URL=postgres://postgres:x@localhost:5433/postgres cargo test -p gapura-control --test it accounts::
//! ```

mod accounts;
mod audit;
mod common;
mod config_endpoint;
mod configuration;
mod consumers;
mod data_planes;
mod grants;
mod identity;
mod jwt;
mod policies;
mod rate_limit;
mod signup;
mod store_tls;
mod workspaces;
