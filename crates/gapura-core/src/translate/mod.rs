//! `translate(&Snapshot, &Settings) -> Translation`: the pure heart of Gapura.
//! Steps: accept GatewayClasses -> build listeners -> attach routes -> assemble Config + Gateway status.

mod gateway_class;

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::snapshot::{Settings, Snapshot};
use crate::status::StatusPatch;

/// Result of one translation pass. Status order: GatewayClass, Gateway, HTTPRoute.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Translation {
    pub config: Config,
    pub status: Vec<StatusPatch>,
}

pub fn translate(snap: &Snapshot, settings: &Settings) -> Translation {
    let mut status = Vec::new();
    let _classes = gateway_class::accept(snap, settings, &mut status);
    Translation {
        config: Config::default(),
        status,
    }
}
