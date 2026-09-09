//! Step 1 of translation: which GatewayClasses are ours.

use std::collections::BTreeSet;

use crate::snapshot::{Settings, Snapshot};
use crate::status::{reasons, types, Condition, ConditionStatus, StatusPatch};

/// Accept every GatewayClass whose controllerName is ours and return their names.
pub(crate) fn accept(
    snap: &Snapshot,
    settings: &Settings,
    status: &mut Vec<StatusPatch>,
) -> BTreeSet<String> {
    let mut ours = BTreeSet::new();
    for (name, gc) in &snap.gateway_classes {
        if gc.spec.controller_name != settings.controller_name {
            continue;
        }
        ours.insert(name.clone());
        status.push(StatusPatch::GatewayClass {
            name: name.clone(),
            conditions: vec![Condition::new(
                types::ACCEPTED,
                ConditionStatus::True,
                reasons::ACCEPTED,
                "Handled by Gapura",
                gc.metadata.generation,
            )],
        });
    }
    ours
}
