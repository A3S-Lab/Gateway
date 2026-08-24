//! Exact-generation lifecycle for private Runtime Service routes.
//!
//! A managed binding is a real Gateway router/service pair backed by one
//! generation-bound loopback Runtime endpoint. The durable store owns only
//! this overlay; the operator's base ACL remains the desired-state authority.

mod model;
mod persistence;
mod store;

pub use model::{
    ManagedServiceBinding, ManagedServiceBindingIdentity, ManagedServiceBindingRequest,
    ManagedServiceHealthCheck, ManagedServicePhase, ManagedServiceStatus,
};
pub(crate) use model::{
    StoredManagedServiceBinding, MANAGED_SERVICE_MIDDLEWARE_NAME, MANAGED_SERVICE_NAME_PREFIX,
};
pub(crate) use store::ManagedServiceStore;

#[cfg(test)]
mod tests;
