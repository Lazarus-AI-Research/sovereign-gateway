//! RBAC: actions and authorization policy.

use crate::model::Role;

/// A guarded operation in the admin surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Issue / revoke / edit virtual keys.
    ManageKeys,
    /// View spend and telemetry.
    ViewSpend,
    /// Edit routing/provider/installation config.
    EditConfig,
    /// Create teams, add/remove members, set roles.
    ManageMembers,
    /// Read the model catalog and own profile.
    ReadCatalog,
}

impl Action {
    /// The minimum role required to perform this action.
    pub fn min_role(self) -> Role {
        match self {
            Action::ManageKeys
            | Action::EditConfig
            | Action::ManageMembers => Role::Admin,
            // Members can view their own spend and read the catalog.
            Action::ViewSpend | Action::ReadCatalog => Role::Member,
        }
    }
}

/// Authorize `role` to perform `action`. Returns `Forbidden` if under-privileged.
pub fn authorize(role: Role, action: Action) -> crate::Result<()> {
    if role.at_least(action.min_role()) {
        Ok(())
    } else {
        Err(crate::Error::Forbidden(format!(
            "role {} cannot perform {:?}",
            role.as_str(),
            action
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precedence() {
        assert!(authorize(Role::Admin, Action::ManageKeys).is_ok());
        assert!(authorize(Role::Member, Action::ManageKeys).is_err());
        assert!(authorize(Role::Member, Action::ViewSpend).is_ok());
        assert!(authorize(Role::Member, Action::ViewSpend).is_ok());
        assert!(authorize(Role::Member, Action::ReadCatalog).is_ok());
        assert!(authorize(Role::Member, Action::EditConfig).is_err());
    }
}
