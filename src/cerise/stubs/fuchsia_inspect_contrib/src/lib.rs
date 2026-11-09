// Cerise stub for fuchsia_inspect_contrib.
// Real inspect_contrib provides BoundedListNode and other helper types.
// for component-manager bring-up we only need the API surface to compile component_manager diagnostics.

pub mod nodes {
    use fuchsia_inspect::Node;

    /// Stub bounded list node — keeps a rolling list of inspect nodes.
    pub struct BoundedListNode {
        _node: Node,
    }

    impl BoundedListNode {
        pub fn new(node: Node, _capacity: usize) -> Self {
            Self { _node: node }
        }

        pub fn add_entry<F: FnOnce(&Node)>(&self, _callback: F) {}
        pub fn len(&self) -> usize { 0 }
        pub fn capacity(&self) -> usize { 0 }
    }
}
