// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::removal_deadline::RemovalDeadline;
use driver_manager_driver_host::DriverHost;
use driver_manager_types::{Collection, ShutdownState};
use fuchsia_async as fasync;
use futures::channel::oneshot;
use log::{info, warn};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::{Rc, Weak};

pub type NodeId = u32;

#[derive(Clone)]
pub struct NodeInfo {
    pub name: String,
    pub driver_url: String,
    pub collection: Collection,
    pub state: ShutdownState,
    pub host: Option<Rc<dyn DriverHost>>,
}

const REMOVAL_TIMEOUT_DURATION: zx::MonotonicDuration = zx::MonotonicDuration::from_seconds(15);

pub struct NodeRemovalTracker {
    fully_enumerated: bool,
    next_node_id: NodeId,
    remaining_pkg_nodes: HashSet<NodeId>,
    remaining_non_pkg_nodes: HashSet<NodeId>,
    nodes: HashMap<NodeId, NodeInfo>,
    pkg_callback: Option<oneshot::Sender<zx::Status>>,
    all_callback: Option<oneshot::Sender<zx::Status>>,
    removal_deadline: RemovalDeadline,
    timeout_task: Option<fasync::Task<()>>,
}

impl NodeRemovalTracker {
    pub fn new() -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self {
            fully_enumerated: false,
            next_node_id: 0,
            remaining_pkg_nodes: HashSet::new(),
            remaining_non_pkg_nodes: HashSet::new(),
            nodes: HashMap::new(),
            pkg_callback: None,
            all_callback: None,
            removal_deadline: RemovalDeadline::default(),
            timeout_task: None,
        }))
    }

    fn start_timeout_task(&mut self, weak_self: Weak<RefCell<Self>>) {
        if let Some(task) = self.timeout_task.take() {
            std::mem::drop(task.abort());
        }

        self.timeout_task = Some(fasync::Task::local(async move {
            fasync::Timer::new(REMOVAL_TIMEOUT_DURATION).await;
            if let Some(strong_self) = weak_self.upgrade() {
                strong_self.borrow_mut().on_removal_timeout(weak_self);
            }
        }));
    }

    pub fn register_node(&mut self, info: NodeInfo) -> NodeId {
        if info.state == ShutdownState::Destroyed {
            return self.next_node_id;
        }

        if info.collection == Collection::Package {
            self.remaining_pkg_nodes.insert(self.next_node_id);
        } else {
            self.remaining_non_pkg_nodes.insert(self.next_node_id);
        }
        self.nodes.insert(self.next_node_id, info);
        let id = self.next_node_id;
        self.next_node_id += 1;
        id
    }

    pub fn notify(&mut self, id: NodeId, state: ShutdownState, _weak_self: Weak<RefCell<Self>>) {
        let collection = {
            let node_info = self.nodes.get_mut(&id).expect("Tried to Notify without registering!");
            node_info.state = state;
            node_info.collection
        };

        if state == ShutdownState::Destroyed {
            if collection == Collection::Package {
                self.remaining_pkg_nodes.remove(&id);
            } else {
                self.remaining_non_pkg_nodes.remove(&id);
            }
            self.check_removal_done();
        }
    }

    pub fn finish_enumeration(&mut self, weak_self: Weak<RefCell<Self>>) {
        self.fully_enumerated = true;
        self.start_timeout_task(weak_self);
        self.check_removal_done();
    }

    pub fn set_pkg_callback(&mut self, callback: oneshot::Sender<zx::Status>) {
        self.removal_deadline.reset();
        self.pkg_callback = Some(callback);
    }

    pub fn set_all_callback(&mut self, callback: oneshot::Sender<zx::Status>) {
        self.removal_deadline.reset();
        self.all_callback = Some(callback);
    }

    fn on_removal_timeout(&mut self, weak_self: Weak<RefCell<Self>>) {
        let expired = self.removal_deadline.record_timeout();
        warn!(
            "Removal hanging, nodes remaining: {} pkg, {} pkg+boot",
            self.remaining_pkg_nodes.len(),
            self.remaining_pkg_nodes.len() + self.remaining_non_pkg_nodes.len()
        );
        for node in self.nodes.values() {
            if node.state != ShutdownState::Destroyed && node.state != ShutdownState::Prestop {
                if node.state == ShutdownState::WaitingOnDriver
                    && let Some(host) = &node.host
                {
                    host.trigger_stack_trace();
                }
                warn!("  '{}' ('{}'): {}", node.name, node.driver_url, node.state);
            }
        }
        if expired {
            warn!(
                "Driver removal did not reach its acknowledgement barrier after {} attempts",
                self.removal_deadline.timeout_count()
            );
            self.complete_waiters(zx::Status::TIMED_OUT);
            self.timeout_task = None;
            return;
        }
        self.start_timeout_task(weak_self);
    }

    fn complete_waiters(&mut self, status: zx::Status) {
        if let Some(sender) = self.pkg_callback.take() {
            let _ = sender.send(status);
        }
        if let Some(sender) = self.all_callback.take() {
            let _ = sender.send(status);
        }
    }

    fn check_removal_done(&mut self) {
        if !self.fully_enumerated {
            return;
        }

        if self.pkg_callback.is_some() && self.remaining_pkg_nodes.is_empty() {
            info!("NodeRemovalTracker: package removal completed");
            if let Some(sender) = self.pkg_callback.take() {
                let _ = sender.send(zx::Status::OK);
            }
        }
        if self.all_callback.is_some()
            && self.remaining_pkg_nodes.is_empty()
            && self.remaining_non_pkg_nodes.is_empty()
        {
            info!("NodeRemovalTracker: all nodes removed");
            if let Some(sender) = self.all_callback.take() {
                let _ = sender.send(zx::Status::OK);
            }
            // Cancel timeout task.
            if let Some(timeout_task) = self.timeout_task.take() {
                std::mem::drop(timeout_task.abort());
            }
            self.nodes.clear();
        }
    }
}
