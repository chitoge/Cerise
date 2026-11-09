// Copyright 2024 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// CERISE: rkyv/lz4 escrow fast-boot path stripped. Stubs return no-op results.

use crate::composite_node_spec_manager::CompositeNodeSpecManager;
use crate::indexer::*;
use crate::resolved_driver::ResolvedDriver;
use fidl_fuchsia_component_sandbox as fsandbox;
use fidl_fuchsia_process_lifecycle as flifecycle;
use std::collections::HashMap;
use std::rc::Rc;

pub struct ResumedState {
    pub notifier: Option<zx::NullableHandle>,
    pub composite_specs: CompositeNodeSpecManager,
    pub boot_repo: Option<Vec<ResolvedDriver>>,
    pub base_repo: Option<BaseRepo>,
    pub ephemeral_repo: HashMap<cm_types::Url, ResolvedDriver>,
}

// Returns whether there were any base drivers that loaded from the resume state.
pub fn apply_state(_resume_state: ResumedState, _index: Rc<Indexer>) -> bool {
    false
}

pub async fn handle_stall(
    _index: Rc<Indexer>,
    _lifecycle_control_handle: &flifecycle::LifecycleControlHandle,
    _outgoing_directory: zx::Channel,
    _capability_store: &fsandbox::CapabilityStoreProxy,
    _id_gen: &sandbox::CapabilityIdGenerator,
    _dict_id: u64,
) -> Result<(), anyhow::Error> {
    Ok(())
}

pub async fn resume_state(
    _capability_store: &fsandbox::CapabilityStoreProxy,
    _id_gen: &sandbox::CapabilityIdGenerator,
    _dict_id: u64,
) -> Result<ResumedState, anyhow::Error> {
    Ok(ResumedState {
        notifier: None,
        composite_specs: CompositeNodeSpecManager::new(),
        boot_repo: None,
        base_repo: None,
        ephemeral_repo: HashMap::new(),
    })
}
