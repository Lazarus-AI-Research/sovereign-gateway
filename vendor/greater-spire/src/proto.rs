//! Generated bindings for the subset of the SPIRE v1.15.3 agent-facing server API used here.
//!
//! SPIRE publishes these protobufs through `spire-api-sdk`, but does not publish a
//! Rust client for the agent-facing server APIs. The checked-in schemas preserve
//! the upstream package, service, method, and field numbers. Unknown fields added
//! by newer servers are ignored by protobuf as intended.

pub mod spire {
    pub mod api {
        pub mod types {
            tonic::include_proto!("spire.api.types");
        }

        pub mod server {
            pub mod agent {
                pub mod v1 {
                    tonic::include_proto!("spire.api.server.agent.v1");
                }
            }
            pub mod bundle {
                pub mod v1 {
                    tonic::include_proto!("spire.api.server.bundle.v1");
                }
            }
            pub mod entry {
                pub mod v1 {
                    tonic::include_proto!("spire.api.server.entry.v1");
                }
            }
            pub mod svid {
                pub mod v1 {
                    tonic::include_proto!("spire.api.server.svid.v1");
                }
            }
        }
    }
}

pub use spire::api::server::agent::v1 as agent;
pub use spire::api::server::bundle::v1 as bundle;
pub use spire::api::server::entry::v1 as entry;
pub use spire::api::server::svid::v1 as svid;
pub use spire::api::types;
