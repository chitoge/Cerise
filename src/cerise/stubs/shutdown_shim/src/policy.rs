#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalAction {
    Poweroff,
    Reboot,
    RebootToBootloader,
    RebootToRecovery,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BeginError {
    AlreadyPending,
}

#[derive(Debug, Default)]
pub struct TerminalTransition {
    action: Option<TerminalAction>,
}

impl TerminalTransition {
    pub fn action(&self) -> Option<TerminalAction> {
        self.action
    }

    pub fn begin(&mut self, action: TerminalAction) -> Result<(), BeginError> {
        if self.action.is_some() {
            return Err(BeginError::AlreadyPending);
        }
        self.action = Some(action);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transition_is_one_shot() {
        let mut transition = TerminalTransition::default();
        assert_eq!(transition.action(), None);
        assert_eq!(transition.begin(TerminalAction::Poweroff), Ok(()));
        assert_eq!(transition.action(), Some(TerminalAction::Poweroff));
        assert_eq!(
            transition.begin(TerminalAction::Reboot),
            Err(BeginError::AlreadyPending)
        );
        assert_eq!(transition.action(), Some(TerminalAction::Poweroff));
    }
}
