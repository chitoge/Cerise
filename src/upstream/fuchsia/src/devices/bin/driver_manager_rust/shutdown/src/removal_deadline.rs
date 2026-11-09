// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub const MAX_REMOVAL_TIMEOUTS: u32 = 3;

#[derive(Debug, Default)]
pub struct RemovalDeadline {
    timeout_count: u32,
}

impl RemovalDeadline {
    pub fn reset(&mut self) {
        self.timeout_count = 0;
    }

    pub fn record_timeout(&mut self) -> bool {
        self.timeout_count += 1;
        self.expired()
    }

    pub fn timeout_count(&self) -> u32 {
        self.timeout_count
    }

    pub fn expired(&self) -> bool {
        self.timeout_count >= MAX_REMOVAL_TIMEOUTS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deadline_expires_on_third_timeout_and_resets() {
        let mut deadline = RemovalDeadline::default();
        assert!(!deadline.record_timeout());
        assert!(!deadline.record_timeout());
        assert!(deadline.record_timeout());
        assert_eq!(deadline.timeout_count(), MAX_REMOVAL_TIMEOUTS);

        deadline.reset();
        assert_eq!(deadline.timeout_count(), 0);
        assert!(!deadline.expired());
    }
}
