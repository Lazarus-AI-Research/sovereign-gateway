//! Authenticated principals resolved by the auth layer.

use crate::ids::{Id, Timestamp};
use crate::model::{ApiKey, Role, User};

/// The result of verifying a `yb_…` bearer token: the key plus its owning user.
#[derive(Debug, Clone)]
pub struct KeyAuth {
    pub user: User,
    pub api_key: ApiKey,
}

/// An authenticated console session — a logged-in [`User`] (from the session
/// cookie). Authorization is by [`Role`].
#[derive(Debug, Clone)]
pub struct Principal {
    pub user_id: Id,
    pub username: String,
    pub role: Role,
    pub expires_at: Timestamp,
}

impl Principal {
    pub fn role(&self) -> Role {
        self.role
    }
    pub fn is_admin(&self) -> bool {
        self.role == Role::Admin
    }
}
