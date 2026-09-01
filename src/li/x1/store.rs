//! Provisioning state: the task store and the destination store.
//!
//! These own what the ADMF has provisioned. Two invariants are enforced here
//! rather than left to the caller, because both are the kind of thing that
//! reads as working and delivers nothing:
//!
//! * **A task delivers only to the DIDs it names.** `listOfDIDs` is not a
//!   hint. [`TaskStore::destinations_for`] resolves a task to exactly the
//!   destinations it referenced, and activation refuses a task naming a DID
//!   that does not exist.
//! * **A destination still referenced by a task cannot be removed.** Removing
//!   it would leave the task provisioned and delivering nowhere, which is the
//!   worst available outcome for a warrant.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use dashmap::DashMap;

use super::error::{ErrorCode, X1Error};
use super::message::{
    DestinationDetails, DestinationResponseDetails, DestinationStatus, TaskDetails,
    TaskResponseDetails, TaskStatus,
};
use super::types::{
    DId, DestinationDeliveryStatus, DeliveryType, ProvisioningStatus, Timestamp, XId,
};
use crate::li::target::{MatchedParty, TargetStore};

/// Whether this node can deliver X3 (content of communication).
///
/// X1 and X2 are backend-independent — provisioning is HTTPS and IRI is
/// signalling, so both work identically on every media backend. X3 carries the
/// content, and the TS 103 221-2 framing lives in the media engine, so only the
/// native `siphon-rtp` backend can emit it.
///
/// This is a capability the task store is told about rather than one it infers,
/// so the same store is testable without a media backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentCapability {
    /// The media engine can frame and deliver X3.
    Available,
    /// It cannot, because `media.backend` is one that has no X3 framer.
    ///
    /// Carries the backend name so the refusal can say which.
    WrongBackend {
        /// The configured `media.backend`.
        backend: &'static str,
    },
    /// The backend is right, but the engine control contract this build is
    /// pinned to carries no verb for attaching an X3 stream.
    ///
    /// This is a real state, not a placeholder: until `siphon-rtp-proto`
    /// publishes the attach/detach verbs there is nothing to send, so a
    /// content warrant is refused rather than accepted and silently delivering
    /// nothing. See [`engine_supports_content`].
    EngineContractLacksVerb,
}

impl ContentCapability {
    /// Whether X3 delivery is possible on this node.
    pub fn is_available(self) -> bool {
        matches!(self, Self::Available)
    }

    /// Why content cannot be delivered, for the `ErrorResponse` description.
    pub fn refusal_reason(self) -> String {
        match self {
            Self::Available => String::new(),
            Self::WrongBackend { backend } => format!(
                "media.backend is {backend:?} and ETSI TS 103 221-2 content framing is \
                 implemented in the siphon-rtp media engine only"
            ),
            Self::EngineContractLacksVerb => {
                "the pinned siphon-rtp control contract carries no verb for attaching an X3 \
                 content stream, so no content could be delivered for this warrant"
                    .to_string()
            }
        }
    }
}

/// Whether the media-engine control contract this build is pinned to can carry
/// an X3 content stream.
///
/// ETSI TS 103 221-2 framing is implemented in the media engine; the signalling
/// plane provisions it over the engine's control protocol.
///
/// `true` since `siphon-rtp-proto` 0.3.1, which carries `AttachX3` /
/// `DetachX3`. siphon issues them from the dispatcher when a content warrant
/// matches a dialog-forming request, so whether a given node can deliver
/// content is now purely a question of `media.backend`.
pub const fn engine_supports_content() -> bool {
    true
}

/// A warrant that matched a message, and which end of the call it names.
#[derive(Debug, Clone)]
pub struct TaskMatch {
    /// The provisioned task.
    pub task: StoredTask,
    /// Which party the warrant names — the reference point every delivered
    /// packet's direction is defined against.
    pub party: MatchedParty,
}

/// A provisioned task, with the bookkeeping `GetTaskDetails` reports.
#[derive(Debug, Clone)]
pub struct StoredTask {
    /// What the ADMF provisioned.
    pub details: TaskDetails,
    /// When it was activated.
    pub activated_at: SystemTime,
    /// When it was last modified, if it has been.
    pub modified_at: Option<SystemTime>,
    /// How many `ModifyTask` messages have been applied.
    pub modification_count: i64,
    /// When product last flowed for this task.
    pub last_intercept_at: Option<SystemTime>,
}

impl StoredTask {
    /// Render as a `TaskResponseDetails` for a query response.
    pub fn to_response_details(&self) -> TaskResponseDetails {
        TaskResponseDetails {
            task_details: self.details.clone(),
            task_status: TaskStatus {
                // A task only reaches the store once it has been fully
                // provisioned; anything that could fail was refused at
                // activation with an ErrorResponse.
                provisioning_status: ProvisioningStatus::Complete,
                list_of_faults: Vec::new(),
                time_of_last_intercept: self.last_intercept_at.map(Timestamp::from_system_time),
                time_of_last_modification: self.modified_at.map(Timestamp::from_system_time),
                number_of_modifications: Some(self.modification_count),
            },
        }
    }
}

/// A provisioned destination.
#[derive(Debug, Clone)]
pub struct StoredDestination {
    /// What the ADMF provisioned.
    pub details: DestinationDetails,
    /// When it was created.
    pub created_at: SystemTime,
    /// Whether delivery to it is currently working.
    pub delivery_status: DestinationDeliveryStatus,
}

impl StoredDestination {
    /// Render as a `DestinationResponseDetails` for a query response.
    pub fn to_response_details(&self) -> DestinationResponseDetails {
        DestinationResponseDetails {
            destination_details: self.details.clone(),
            destination_status: DestinationStatus {
                destination_delivery_status: self.delivery_status,
                list_of_faults: Vec::new(),
            },
        }
    }
}

/// The destination store, keyed by DID.
#[derive(Debug, Clone, Default)]
pub struct DestinationStore {
    destinations: Arc<DashMap<DId, StoredDestination>>,
}

impl DestinationStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a destination. Refuses a DID that already exists.
    pub fn create(&self, details: DestinationDetails) -> Result<(), X1Error> {
        let d_id = details.d_id;
        if self.destinations.contains_key(&d_id) {
            return Err(X1Error::new(
                ErrorCode::DidAlreadyExists,
                format!("destination {d_id} is already provisioned"),
            ));
        }
        // siphon delivers over IP; a destination it could never reach is
        // refused now rather than at the first intercept.
        if details.delivery_address.socket_addr().is_none() {
            return Err(X1Error::new(
                ErrorCode::UnsupportedDeliveryAddressType,
                format!(
                    "delivery address form {:?} cannot be used for X2/X3 delivery — \
                     siphon delivers to ipAddressAndPort",
                    details.delivery_address.kind()
                ),
            ));
        }
        self.destinations.insert(
            d_id,
            StoredDestination {
                details,
                created_at: SystemTime::now(),
                delivery_status: DestinationDeliveryStatus::ActiveAndWorking,
            },
        );
        Ok(())
    }

    /// Modify an existing destination. Refuses a DID that does not exist.
    pub fn modify(&self, details: DestinationDetails) -> Result<(), X1Error> {
        let d_id = details.d_id;
        let Some(mut existing) = self.destinations.get_mut(&d_id) else {
            return Err(X1Error::new(
                ErrorCode::DidDoesNotExist,
                format!("destination {d_id} is not provisioned"),
            ));
        };
        if details.delivery_address.socket_addr().is_none() {
            return Err(X1Error::new(
                ErrorCode::UnsupportedDeliveryAddressType,
                format!(
                    "delivery address form {:?} cannot be used for X2/X3 delivery",
                    details.delivery_address.kind()
                ),
            ));
        }
        existing.details = details;
        Ok(())
    }

    /// Remove a destination.
    ///
    /// The caller must have already checked that no task references it — see
    /// [`TaskStore::tasks_referencing`].
    pub fn remove(&self, d_id: DId) -> Result<StoredDestination, X1Error> {
        self.destinations
            .remove(&d_id)
            .map(|(_, destination)| destination)
            .ok_or_else(|| {
                X1Error::new(
                    ErrorCode::DidDoesNotExist,
                    format!("destination {d_id} is not provisioned"),
                )
            })
    }

    /// Remove every destination.
    pub fn remove_all(&self) {
        self.destinations.clear();
    }

    /// Look one up.
    pub fn get(&self, d_id: DId) -> Option<StoredDestination> {
        self.destinations.get(&d_id).map(|entry| entry.clone())
    }

    /// Whether a DID is provisioned.
    pub fn contains(&self, d_id: DId) -> bool {
        self.destinations.contains_key(&d_id)
    }

    /// Every provisioned destination, ordered by DID for a stable response.
    pub fn list(&self) -> Vec<StoredDestination> {
        let mut all: Vec<StoredDestination> = self
            .destinations
            .iter()
            .map(|entry| entry.value().clone())
            .collect();
        all.sort_by_key(|destination| destination.details.d_id);
        all
    }

    /// Every provisioned DID, sorted.
    pub fn ids(&self) -> Vec<DId> {
        let mut ids: Vec<DId> = self.destinations.iter().map(|entry| *entry.key()).collect();
        ids.sort_unstable();
        ids
    }

    /// How many destinations are provisioned.
    pub fn len(&self) -> usize {
        self.destinations.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.destinations.is_empty()
    }

    /// Mark a destination's delivery state, for `ReportDestinationIssue`.
    pub fn set_delivery_status(&self, d_id: DId, status: DestinationDeliveryStatus) -> bool {
        match self.destinations.get_mut(&d_id) {
            Some(mut destination) => {
                destination.delivery_status = status;
                true
            }
            None => false,
        }
    }
}

/// The task store, keyed by XID.
#[derive(Debug, Clone)]
pub struct TaskStore {
    tasks: Arc<DashMap<XId, StoredTask>>,
    /// The matching index, kept in step with `tasks` on every mutation so a
    /// warrant is never provisioned but unfindable, or findable but gone.
    index: TargetStore,
    destinations: DestinationStore,
    content_capability: ContentCapability,
    /// Bumped whenever a change makes a previous matching decision wrong.
    ///
    /// The dispatcher caches per-session decisions so it does not re-match
    /// every message of a dialog, and this is what stops that cache outliving
    /// its premise: an `ActivateTask` has to take effect on calls already in
    /// progress, so a session decided as "no warrant" a moment earlier must be
    /// decided again rather than trusted.
    generation: Arc<AtomicU64>,
}

impl TaskStore {
    /// A store over the given destination store and content capability.
    pub fn new(destinations: DestinationStore, content_capability: ContentCapability) -> Self {
        Self {
            tasks: Arc::new(DashMap::new()),
            index: TargetStore::new(),
            destinations,
            content_capability,
            generation: Arc::new(AtomicU64::new(0)),
        }
    }

    /// The current provisioning generation.
    ///
    /// A cached matching decision is only usable while this has not moved.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Invalidate every cached matching decision.
    ///
    /// Called from each mutation that can change what matches. It is
    /// deliberately coarse: a warrant provisioned or withdrawn is rare and a
    /// missed interception is not survivable, so every session is re-decided
    /// rather than reasoning about which ones could have been affected.
    fn bump_generation(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
    }

    /// The matching index this store maintains.
    ///
    /// The dispatcher consults this on every message; it is read-only from
    /// there, because only provisioning may change what is intercepted.
    pub fn index(&self) -> &TargetStore {
        &self.index
    }

    /// Tasks whose warrant matches the identities on one SIP message, each with
    /// the party it matched.
    ///
    /// This is the enforcement path: it runs for every message, on every leg,
    /// regardless of what the operator's script does.
    pub fn match_message(
        &self,
        request_uri: Option<&str>,
        from_uri: Option<&str>,
        to_uri: Option<&str>,
        source_ip: Option<std::net::IpAddr>,
    ) -> Vec<TaskMatch> {
        self.index
            .match_message(request_uri, from_uri, to_uri, source_ip)
            .into_iter()
            .filter_map(|matched| {
                self.get(matched.x_id).map(|task| TaskMatch {
                    task,
                    party: matched.party,
                })
            })
            .collect()
    }

    /// The destination store this task store resolves DIDs against.
    pub fn destinations(&self) -> &DestinationStore {
        &self.destinations
    }

    /// Whether this node can deliver content.
    pub fn content_capability(&self) -> ContentCapability {
        self.content_capability
    }

    /// Check everything that must hold before a task can be provisioned.
    ///
    /// Split out from [`Self::activate`] so `ModifyTask` applies the same
    /// rules: a modification that made a task undeliverable would be just as
    /// bad as an activation that did.
    fn validate(&self, details: &TaskDetails) -> Result<(), X1Error> {
        // -- target identifiers we can actually match on --------------
        let unsupported = details.unsupported_identifiers();
        if !unsupported.is_empty() {
            return Err(X1Error::new(
                ErrorCode::UnsupportedTargetIdentifierType,
                format!(
                    "target identifier type(s) {} cannot be intercepted by a SIP network element",
                    unsupported.join(", ")
                ),
            ));
        }

        // -- destination-set references are out of profile -------------
        if !details.list_of_dsids.is_empty() {
            return Err(X1Error::new(
                ErrorCode::UnsupportedRequest,
                format!(
                    "listOfDIDs names {} destination set(s) (dSId); destination sets are \
                     generic objects and are not supported by this network element",
                    details.list_of_dsids.len()
                ),
            ));
        }

        // -- at least one destination, and every one must exist --------
        if details.list_of_dids.is_empty() {
            return Err(X1Error::new(
                ErrorCode::InvalidCombinationOfDeliveryTypeAndDestinations,
                "listOfDIDs is empty — a task must name at least one destination to deliver to",
            ));
        }
        let missing: Vec<String> = details
            .list_of_dids
            .iter()
            .filter(|d_id| !self.destinations.contains(**d_id))
            .map(|d_id| d_id.to_string())
            .collect();
        if !missing.is_empty() {
            return Err(X1Error::new(
                ErrorCode::DidDoesNotExist,
                format!("destination(s) {} are not provisioned", missing.join(", ")),
            ));
        }

        // -- the named destinations must cover what the task delivers --
        //
        // Coverage is across the whole named set, not per destination: the
        // ordinary split-MDF deployment points a task at one X2Only collector
        // for IRI and one X3Only collector for content, and neither accepts
        // both. What must not happen is an interface with nowhere to go — a
        // task delivering content whose destinations all refuse content would
        // be accepted and then silently drop the product.
        let accepted: Vec<DeliveryType> = details
            .list_of_dids
            .iter()
            .filter_map(|d_id| self.destinations.get(*d_id))
            .map(|destination| destination.details.delivery_type)
            .collect();

        if details.delivery_type.includes_iri()
            && !accepted.iter().any(|kind| kind.includes_iri())
        {
            return Err(X1Error::new(
                ErrorCode::InvalidCombinationOfDeliveryTypeAndDestinations,
                format!(
                    "task deliveryType {} requires X2, but none of its destinations accept it",
                    details.delivery_type
                ),
            ));
        }
        if details.delivery_type.includes_content()
            && !accepted.iter().any(|kind| kind.includes_content())
        {
            return Err(X1Error::new(
                ErrorCode::InvalidCombinationOfDeliveryTypeAndDestinations,
                format!(
                    "task deliveryType {} requires X3, but none of its destinations accept it",
                    details.delivery_type
                ),
            ));
        }

        // -- this node must be able to deliver content at all ----------
        // The refusal that matters most. Accepting a warrant and then
        // delivering no content reads as provisioned at the ADMF, satisfies
        // every acknowledgement, and the absence only surfaces when someone
        // goes looking for product that was never sent.
        if details.delivery_type.includes_content() && !self.content_capability.is_available() {
            return Err(X1Error::new(
                ErrorCode::InvalidCombinationOfDeliveryTypeAndDestinations,
                format!(
                    "task deliveryType {} requires X3 content delivery, which this node cannot \
                     perform: {}",
                    details.delivery_type,
                    self.content_capability.refusal_reason()
                ),
            ));
        }

        Ok(())
    }

    /// Activate a task. Refuses an XID that already exists.
    pub fn activate(&self, details: TaskDetails) -> Result<(), X1Error> {
        let x_id = details.x_id;
        if self.tasks.contains_key(&x_id) {
            return Err(X1Error::new(
                ErrorCode::XidAlreadyExists,
                format!("task {x_id} is already provisioned"),
            ));
        }
        self.validate(&details)?;
        self.index.index(x_id, &details.target_identifiers);
        self.tasks.insert(
            x_id,
            StoredTask {
                details,
                activated_at: SystemTime::now(),
                modified_at: None,
                modification_count: 0,
                last_intercept_at: None,
            },
        );
        self.bump_generation();
        Ok(())
    }

    /// Modify a task. Refuses an XID that does not exist.
    ///
    /// The new details are validated exactly as an activation would be, and
    /// the task is left untouched if they do not pass — a rejected
    /// modification must not deactivate a live warrant.
    pub fn modify(&self, details: TaskDetails) -> Result<(), X1Error> {
        let x_id = details.x_id;
        if !self.tasks.contains_key(&x_id) {
            return Err(X1Error::new(
                ErrorCode::XidDoesNotExist,
                format!("task {x_id} is not provisioned"),
            ));
        }
        self.validate(&details)?;
        let task_identifiers = details.target_identifiers.clone();
        let Some(mut task) = self.tasks.get_mut(&x_id) else {
            return Err(X1Error::new(
                ErrorCode::XidDoesNotExist,
                format!("task {x_id} is not provisioned"),
            ));
        };
        // Reindex before storing: a modification that changed the target must
        // stop the old identity matching at the same instant the new one starts.
        self.index.index(x_id, &task_identifiers);
        task.details = details;
        task.modified_at = Some(SystemTime::now());
        task.modification_count += 1;
        // Dropped before the bump so no reader can observe the new generation
        // while this entry is still write-locked.
        drop(task);
        self.bump_generation();
        Ok(())
    }

    /// Deactivate a task.
    pub fn deactivate(&self, x_id: XId) -> Result<StoredTask, X1Error> {
        self.index.remove(x_id);
        self.bump_generation();
        self.tasks
            .remove(&x_id)
            .map(|(_, task)| task)
            .ok_or_else(|| {
                X1Error::new(
                    ErrorCode::XidDoesNotExist,
                    format!("task {x_id} is not provisioned"),
                )
            })
    }

    /// Deactivate every task, returning how many were removed.
    pub fn deactivate_all(&self) -> usize {
        let count = self.tasks.len();
        self.index.clear();
        self.tasks.clear();
        self.bump_generation();
        count
    }

    /// Look one up.
    pub fn get(&self, x_id: XId) -> Option<StoredTask> {
        self.tasks.get(&x_id).map(|entry| entry.clone())
    }

    /// Every provisioned task, ordered by XID for a stable response.
    pub fn list(&self) -> Vec<StoredTask> {
        let mut all: Vec<StoredTask> = self
            .tasks
            .iter()
            .map(|entry| entry.value().clone())
            .collect();
        all.sort_by_key(|task| task.details.x_id);
        all
    }

    /// Every provisioned XID, sorted.
    pub fn ids(&self) -> Vec<XId> {
        let mut ids: Vec<XId> = self.tasks.iter().map(|entry| *entry.key()).collect();
        ids.sort_unstable();
        ids
    }

    /// How many tasks are provisioned.
    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    /// The XIDs of every task referencing a destination.
    ///
    /// `RemoveDestination` consults this: removing a referenced destination
    /// would leave its tasks provisioned and delivering nowhere.
    pub fn tasks_referencing(&self, d_id: DId) -> Vec<XId> {
        let mut referencing: Vec<XId> = self
            .tasks
            .iter()
            .filter(|entry| entry.value().details.list_of_dids.contains(&d_id))
            .map(|entry| *entry.key())
            .collect();
        referencing.sort_unstable();
        referencing
    }

    /// The destinations a task delivers to — exactly the DIDs it names.
    ///
    /// Not "every destination", and not "the first one". A task's product goes
    /// only where the warrant said it should.
    pub fn destinations_for(&self, x_id: XId) -> Vec<StoredDestination> {
        let Some(task) = self.get(x_id) else {
            return Vec::new();
        };
        task.details
            .list_of_dids
            .iter()
            .filter_map(|d_id| self.destinations.get(*d_id))
            .collect()
    }

    /// The destinations a task delivers a given interface's product to.
    ///
    /// A destination provisioned `X2Only` must not receive content, and one
    /// provisioned `X3Only` must not receive IRI, even when the task itself
    /// carries both.
    pub fn destinations_for_interface(
        &self,
        x_id: XId,
        want_content: bool,
    ) -> Vec<StoredDestination> {
        self.destinations_for(x_id)
            .into_iter()
            .filter(|destination| {
                if want_content {
                    destination.details.delivery_type.includes_content()
                } else {
                    destination.details.delivery_type.includes_iri()
                }
            })
            .collect()
    }

    /// Record that product flowed for a task, for `timeOfLastIntercept`.
    pub fn mark_intercept(&self, x_id: XId) {
        if let Some(mut task) = self.tasks.get_mut(&x_id) {
            task.last_intercept_at = Some(SystemTime::now());
        }
    }

    /// Replace the whole task set — used when reloading provisioned state.
    pub fn replace_all(&self, tasks: Vec<TaskDetails>) {
        self.index.clear();
        self.tasks.clear();
        for details in tasks {
            let x_id = details.x_id;
            self.index.index(x_id, &details.target_identifiers);
            self.tasks.insert(
                x_id,
                StoredTask {
                    details,
                    activated_at: SystemTime::now(),
                    modified_at: None,
                    modification_count: 0,
                    last_intercept_at: None,
                },
            );
        }
    }
}

/// Whether a delivery type can be honoured on this node at all.
///
/// Exposed for the config-load gate, which refuses to start a node configured
/// for X3 on a backend that cannot emit it — the same rule as
/// [`TaskStore::validate`], applied earlier.
pub fn content_delivery_supported(
    delivery_type: DeliveryType,
    capability: ContentCapability,
) -> bool {
    !delivery_type.includes_content() || capability.is_available()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::li::x1::types::{IpAddressPort, Port, TargetIdentifier};
    use crate::li::x1::types::DeliveryAddress;
    use std::net::{IpAddr, Ipv4Addr};

    fn destination(delivery_type: DeliveryType) -> DestinationDetails {
        DestinationDetails {
            d_id: DId::generate(),
            friendly_name: Some("test mdf".to_string()),
            delivery_type,
            delivery_address: DeliveryAddress::IpAddressAndPort(IpAddressPort {
                address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)),
                port: Port::Tcp(42069),
            }),
        }
    }

    fn task(delivery_type: DeliveryType, dids: Vec<DId>) -> TaskDetails {
        TaskDetails {
            x_id: XId::generate(),
            target_identifiers: vec![TargetIdentifier::SipUri("sip:alice@example.com".into())],
            delivery_type,
            list_of_dids: dids,
            list_of_dsids: Vec::new(),
            list_of_mediation_details: Vec::new(),
            correlation_id: None,
            implicit_deactivation_allowed: None,
            product_id: None,
            list_of_service_types: Vec::new(),
        }
    }

    fn stores(capability: ContentCapability) -> (DestinationStore, TaskStore) {
        let destinations = DestinationStore::new();
        let tasks = TaskStore::new(destinations.clone(), capability);
        (destinations, tasks)
    }

    fn stores_with_content() -> (DestinationStore, TaskStore) {
        stores(ContentCapability::Available)
    }

    // -- destination lifecycle ------------------------------------------

    #[test]
    fn create_and_look_up_a_destination() {
        let (destinations, _) = stores_with_content();
        let details = destination(DeliveryType::X2AndX3);
        let d_id = details.d_id;
        destinations.create(details).unwrap();
        assert_eq!(destinations.len(), 1);
        assert!(destinations.contains(d_id));
        assert_eq!(destinations.get(d_id).unwrap().details.d_id, d_id);
    }

    #[test]
    fn creating_a_duplicate_did_is_refused() {
        let (destinations, _) = stores_with_content();
        let details = destination(DeliveryType::X2Only);
        destinations.create(details.clone()).unwrap();
        let error = destinations.create(details).unwrap_err();
        assert_eq!(error.code, ErrorCode::DidAlreadyExists);
    }

    #[test]
    fn modifying_an_unknown_did_is_refused() {
        let (destinations, _) = stores_with_content();
        let error = destinations.modify(destination(DeliveryType::X2Only)).unwrap_err();
        assert_eq!(error.code, ErrorCode::DidDoesNotExist);
    }

    #[test]
    fn modify_replaces_the_stored_destination() {
        let (destinations, _) = stores_with_content();
        let mut details = destination(DeliveryType::X2Only);
        destinations.create(details.clone()).unwrap();
        details.friendly_name = Some("renamed".to_string());
        destinations.modify(details.clone()).unwrap();
        assert_eq!(
            destinations.get(details.d_id).unwrap().details.friendly_name,
            Some("renamed".to_string())
        );
    }

    #[test]
    fn a_destination_siphon_cannot_reach_is_refused_at_creation() {
        // Accepting an email or E.164 delivery address would provision a
        // destination that no product could ever be sent to.
        let (destinations, _) = stores_with_content();
        let mut details = destination(DeliveryType::X2Only);
        details.delivery_address = DeliveryAddress::EmailAddress("mdf@example.com".into());
        let error = destinations.create(details).unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsupportedDeliveryAddressType);
    }

    #[test]
    fn removing_an_unknown_did_is_refused() {
        let (destinations, _) = stores_with_content();
        let error = destinations.remove(DId::generate()).unwrap_err();
        assert_eq!(error.code, ErrorCode::DidDoesNotExist);
    }

    // -- task lifecycle --------------------------------------------------

    #[test]
    fn activate_and_look_up_a_task() {
        let (destinations, tasks) = stores_with_content();
        let dest = destination(DeliveryType::X2AndX3);
        let d_id = dest.d_id;
        destinations.create(dest).unwrap();

        let details = task(DeliveryType::X2AndX3, vec![d_id]);
        let x_id = details.x_id;
        tasks.activate(details).unwrap();

        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks.get(x_id).unwrap().details.x_id, x_id);
        assert_eq!(tasks.ids(), vec![x_id]);
    }

    #[test]
    fn activating_a_duplicate_xid_is_refused() {
        let (destinations, tasks) = stores_with_content();
        let dest = destination(DeliveryType::X2Only);
        let d_id = dest.d_id;
        destinations.create(dest).unwrap();
        let details = task(DeliveryType::X2Only, vec![d_id]);
        tasks.activate(details.clone()).unwrap();
        let error = tasks.activate(details).unwrap_err();
        assert_eq!(error.code, ErrorCode::XidAlreadyExists);
    }

    #[test]
    fn a_task_naming_an_unknown_did_is_refused() {
        let (_, tasks) = stores_with_content();
        let error = tasks
            .activate(task(DeliveryType::X2Only, vec![DId::generate()]))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::DidDoesNotExist);
        assert!(tasks.is_empty(), "a refused task must not be stored");
    }

    #[test]
    fn a_task_naming_no_destination_is_refused() {
        let (_, tasks) = stores_with_content();
        let error = tasks.activate(task(DeliveryType::X2Only, vec![])).unwrap_err();
        assert_eq!(
            error.code,
            ErrorCode::InvalidCombinationOfDeliveryTypeAndDestinations
        );
    }

    #[test]
    fn a_task_with_an_unsupported_target_identifier_is_refused_by_name() {
        let (destinations, tasks) = stores_with_content();
        let dest = destination(DeliveryType::X2Only);
        let d_id = dest.d_id;
        destinations.create(dest).unwrap();

        let mut details = task(DeliveryType::X2Only, vec![d_id]);
        details.target_identifiers = vec![TargetIdentifier::Unsupported("gtpuTunnelId".into())];
        let error = tasks.activate(details).unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsupportedTargetIdentifierType);
        assert!(
            error.description.contains("gtpuTunnelId"),
            "the refusal must name the offending type, got: {}",
            error.description
        );
    }

    #[test]
    fn a_task_naming_a_destination_set_is_refused() {
        // Destination sets are generic objects, which are out of profile.
        // Ignoring the reference would deliver somewhere the ADMF did not ask.
        let (destinations, tasks) = stores_with_content();
        let dest = destination(DeliveryType::X2Only);
        let d_id = dest.d_id;
        destinations.create(dest).unwrap();

        let mut details = task(DeliveryType::X2Only, vec![d_id]);
        details.list_of_dsids = vec!["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into()];
        let error = tasks.activate(details).unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsupportedRequest);
    }

    #[test]
    fn deactivating_an_unknown_xid_is_refused() {
        let (_, tasks) = stores_with_content();
        let error = tasks.deactivate(XId::generate()).unwrap_err();
        assert_eq!(error.code, ErrorCode::XidDoesNotExist);
    }

    #[test]
    fn a_deactivated_task_is_gone() {
        let (destinations, tasks) = stores_with_content();
        let dest = destination(DeliveryType::X2Only);
        let d_id = dest.d_id;
        destinations.create(dest).unwrap();
        let details = task(DeliveryType::X2Only, vec![d_id]);
        let x_id = details.x_id;
        tasks.activate(details).unwrap();

        tasks.deactivate(x_id).unwrap();
        assert!(tasks.get(x_id).is_none());
        assert!(tasks.is_empty());
        assert!(tasks.destinations_for(x_id).is_empty());
    }

    #[test]
    fn modify_bumps_the_counters() {
        let (destinations, tasks) = stores_with_content();
        let dest = destination(DeliveryType::X2AndX3);
        let d_id = dest.d_id;
        destinations.create(dest).unwrap();

        let details = task(DeliveryType::X2Only, vec![d_id]);
        let x_id = details.x_id;
        tasks.activate(details.clone()).unwrap();
        assert_eq!(tasks.get(x_id).unwrap().modification_count, 0);

        let mut changed = details;
        changed.delivery_type = DeliveryType::X2AndX3;
        tasks.modify(changed).unwrap();

        let stored = tasks.get(x_id).unwrap();
        assert_eq!(stored.modification_count, 1);
        assert!(stored.modified_at.is_some());
        assert_eq!(stored.details.delivery_type, DeliveryType::X2AndX3);
    }

    #[test]
    fn a_rejected_modification_leaves_the_task_untouched() {
        // A live warrant must not be damaged by a bad ModifyTask.
        let (destinations, tasks) = stores_with_content();
        let dest = destination(DeliveryType::X2Only);
        let d_id = dest.d_id;
        destinations.create(dest).unwrap();

        let details = task(DeliveryType::X2Only, vec![d_id]);
        let x_id = details.x_id;
        tasks.activate(details.clone()).unwrap();

        let mut bad = details;
        bad.list_of_dids = vec![DId::generate()]; // unknown destination
        assert!(tasks.modify(bad).is_err());

        let stored = tasks.get(x_id).expect("the task must survive a rejected modify");
        assert_eq!(stored.details.list_of_dids, vec![d_id]);
        assert_eq!(stored.modification_count, 0);
    }

    #[test]
    fn modifying_an_unknown_xid_is_refused() {
        let (_, tasks) = stores_with_content();
        let error = tasks.modify(task(DeliveryType::X2Only, vec![])).unwrap_err();
        assert_eq!(error.code, ErrorCode::XidDoesNotExist);
    }

    // -- delivery routing -------------------------------------------------

    #[test]
    fn a_task_delivers_only_to_the_dids_it_names() {
        let (destinations, tasks) = stores_with_content();
        let named = destination(DeliveryType::X2AndX3);
        let other = destination(DeliveryType::X2AndX3);
        let named_id = named.d_id;
        destinations.create(named).unwrap();
        destinations.create(other).unwrap();
        assert_eq!(destinations.len(), 2);

        let details = task(DeliveryType::X2AndX3, vec![named_id]);
        let x_id = details.x_id;
        tasks.activate(details).unwrap();

        let resolved = tasks.destinations_for(x_id);
        assert_eq!(resolved.len(), 1, "must not fan out to unnamed destinations");
        assert_eq!(resolved[0].details.d_id, named_id);
    }

    #[test]
    fn interface_scoping_keeps_content_off_an_x2_only_destination() {
        let (destinations, tasks) = stores_with_content();
        let iri_sink = destination(DeliveryType::X2Only);
        let content_sink = destination(DeliveryType::X3Only);
        let iri_id = iri_sink.d_id;
        let content_id = content_sink.d_id;
        destinations.create(iri_sink).unwrap();
        destinations.create(content_sink).unwrap();

        let details = task(DeliveryType::X2AndX3, vec![iri_id, content_id]);
        let x_id = details.x_id;
        tasks.activate(details).unwrap();

        let iri_targets = tasks.destinations_for_interface(x_id, false);
        assert_eq!(iri_targets.len(), 1);
        assert_eq!(iri_targets[0].details.d_id, iri_id);

        let content_targets = tasks.destinations_for_interface(x_id, true);
        assert_eq!(content_targets.len(), 1);
        assert_eq!(content_targets[0].details.d_id, content_id);
    }

    #[test]
    fn a_content_task_pointed_only_at_an_x2_destination_is_refused() {
        let (destinations, tasks) = stores_with_content();
        let dest = destination(DeliveryType::X2Only);
        let d_id = dest.d_id;
        destinations.create(dest).unwrap();

        let error = tasks
            .activate(task(DeliveryType::X2AndX3, vec![d_id]))
            .unwrap_err();
        assert_eq!(
            error.code,
            ErrorCode::InvalidCombinationOfDeliveryTypeAndDestinations
        );
    }

    #[test]
    fn an_iri_task_pointed_only_at_an_x3_destination_is_refused() {
        let (destinations, tasks) = stores_with_content();
        let dest = destination(DeliveryType::X3Only);
        let d_id = dest.d_id;
        destinations.create(dest).unwrap();

        let error = tasks
            .activate(task(DeliveryType::X2Only, vec![d_id]))
            .unwrap_err();
        assert_eq!(
            error.code,
            ErrorCode::InvalidCombinationOfDeliveryTypeAndDestinations
        );
    }

    // -- referential integrity --------------------------------------------

    #[test]
    fn a_referenced_destination_is_reported_as_in_use() {
        let (destinations, tasks) = stores_with_content();
        let dest = destination(DeliveryType::X2Only);
        let d_id = dest.d_id;
        destinations.create(dest).unwrap();

        let details = task(DeliveryType::X2Only, vec![d_id]);
        let x_id = details.x_id;
        tasks.activate(details).unwrap();

        assert_eq!(tasks.tasks_referencing(d_id), vec![x_id]);
    }

    #[test]
    fn an_unreferenced_destination_reports_no_users() {
        let (destinations, tasks) = stores_with_content();
        let dest = destination(DeliveryType::X2Only);
        let d_id = dest.d_id;
        destinations.create(dest).unwrap();
        assert!(tasks.tasks_referencing(d_id).is_empty());
    }

    #[test]
    fn references_clear_when_the_task_is_deactivated() {
        let (destinations, tasks) = stores_with_content();
        let dest = destination(DeliveryType::X2Only);
        let d_id = dest.d_id;
        destinations.create(dest).unwrap();
        let details = task(DeliveryType::X2Only, vec![d_id]);
        let x_id = details.x_id;
        tasks.activate(details).unwrap();

        tasks.deactivate(x_id).unwrap();
        assert!(tasks.tasks_referencing(d_id).is_empty());
    }

    // -- the content-capability gate --------------------------------------

    #[test]
    fn an_x2_only_task_is_accepted_without_a_content_capable_backend() {
        // X1 and X2 are backend-independent; only X3 is gated.
        let (destinations, tasks) = stores(ContentCapability::WrongBackend {
            backend: "rtpengine",
        });
        let dest = destination(DeliveryType::X2Only);
        let d_id = dest.d_id;
        destinations.create(dest).unwrap();
        tasks
            .activate(task(DeliveryType::X2Only, vec![d_id]))
            .expect("X2Only must work on every media backend");
    }

    #[test]
    fn a_content_task_is_refused_without_a_content_capable_backend() {
        for delivery_type in [DeliveryType::X3Only, DeliveryType::X2AndX3] {
            let (destinations, tasks) = stores(ContentCapability::WrongBackend {
                backend: "rtpengine",
            });
            let dest = destination(DeliveryType::X2AndX3);
            let d_id = dest.d_id;
            destinations.create(dest).unwrap();

            let error = tasks
                .activate(task(delivery_type, vec![d_id]))
                .unwrap_err();
            assert_eq!(
                error.code,
                ErrorCode::InvalidCombinationOfDeliveryTypeAndDestinations,
                "{delivery_type} must be refused"
            );
            assert!(
                error.description.contains("rtpengine"),
                "the refusal must name the backend, got: {}",
                error.description
            );
            assert!(
                tasks.is_empty(),
                "a refused warrant must not be stored — it would read as provisioned"
            );
        }
    }

    #[test]
    fn a_content_modification_is_refused_without_a_content_capable_backend() {
        // The gate has to cover ModifyTask too, or an X2Only task could be
        // upgraded to X2andX3 and start silently delivering nothing.
        let (destinations, tasks) = stores(ContentCapability::WrongBackend {
            backend: "rtpproxy",
        });
        let dest = destination(DeliveryType::X2AndX3);
        let d_id = dest.d_id;
        destinations.create(dest).unwrap();

        let details = task(DeliveryType::X2Only, vec![d_id]);
        let x_id = details.x_id;
        tasks.activate(details.clone()).unwrap();

        let mut upgraded = details;
        upgraded.delivery_type = DeliveryType::X2AndX3;
        let error = tasks.modify(upgraded).unwrap_err();
        assert_eq!(
            error.code,
            ErrorCode::InvalidCombinationOfDeliveryTypeAndDestinations
        );
        assert_eq!(
            tasks.get(x_id).unwrap().details.delivery_type,
            DeliveryType::X2Only,
            "the task must keep its original delivery type"
        );
    }

    #[test]
    fn a_content_warrant_is_refused_while_the_engine_contract_lacks_the_verb() {
        // The contract now carries the verbs, so this state is not reachable
        // from `content_capability_for` today. The refusal path is still tested
        // directly: it is what protects an operator whose engine contract goes
        // backwards, and a warrant accepted with nothing to attach would read
        // as provisioned at the ADMF and deliver nothing.
        let (destinations, tasks) = stores(ContentCapability::EngineContractLacksVerb);
        let dest = destination(DeliveryType::X2AndX3);
        let d_id = dest.d_id;
        destinations.create(dest).unwrap();

        let error = tasks
            .activate(task(DeliveryType::X2AndX3, vec![d_id]))
            .unwrap_err();
        assert_eq!(
            error.code,
            ErrorCode::InvalidCombinationOfDeliveryTypeAndDestinations
        );
        assert!(
            error.description.contains("control contract"),
            "the refusal must say why, got: {}",
            error.description
        );
        assert!(tasks.is_empty());
    }

    #[test]
    fn the_engine_content_flag_is_the_single_place_that_changes() {
        // The contract carries AttachX3/DetachX3 as of siphon-rtp-proto 0.3.1
        // and siphon issues them. Pinned so that turning content delivery off
        // again — by regressing the dependency, say — has to be a deliberate
        // edit rather than something a version bump does quietly.
        assert!(
            engine_supports_content(),
            "the siphon-rtp control contract carries AttachX3/DetachX3 since 0.3.1; if this \
             is false the dependency has regressed and every content warrant is being refused"
        );
    }

    #[test]
    fn refusal_reasons_name_the_actual_obstacle() {
        assert!(ContentCapability::Available.refusal_reason().is_empty());
        assert!(ContentCapability::WrongBackend {
            backend: "rtpengine"
        }
        .refusal_reason()
        .contains("rtpengine"));
        assert!(ContentCapability::EngineContractLacksVerb
            .refusal_reason()
            .contains("control contract"));
    }

    #[test]
    fn content_delivery_supported_matches_the_capability_table() {
        let available = ContentCapability::Available;
        let unavailable = ContentCapability::WrongBackend {
            backend: "rtpengine",
        };
        assert!(content_delivery_supported(DeliveryType::X2Only, unavailable));
        assert!(!content_delivery_supported(DeliveryType::X3Only, unavailable));
        assert!(!content_delivery_supported(DeliveryType::X2AndX3, unavailable));
        assert!(content_delivery_supported(DeliveryType::X2Only, available));
        assert!(content_delivery_supported(DeliveryType::X3Only, available));
        assert!(content_delivery_supported(DeliveryType::X2AndX3, available));
    }

    // -- concurrency -------------------------------------------------------

    #[test]
    fn concurrent_activation_is_safe() {
        use std::thread;

        let (destinations, tasks) = stores_with_content();
        let dest = destination(DeliveryType::X2AndX3);
        let d_id = dest.d_id;
        destinations.create(dest).unwrap();

        let mut handles = Vec::new();
        for _ in 0..16 {
            let tasks = tasks.clone();
            handles.push(thread::spawn(move || {
                tasks.activate(task(DeliveryType::X2AndX3, vec![d_id]))
            }));
        }
        for handle in handles {
            handle.join().unwrap().unwrap();
        }
        assert_eq!(tasks.len(), 16);
    }

    #[test]
    fn store_drains_to_baseline_after_a_full_lifecycle() {
        // Per-module leak guard: a batch of complete activate/deactivate
        // cycles must leave the stores exactly as it found them. The classic
        // bug this catches is a per-warrant entry that is inserted and never
        // evicted.
        let (destinations, tasks) = stores_with_content();
        let baseline_tasks = tasks.len();
        let baseline_destinations = destinations.len();

        for _ in 0..500 {
            let dest = destination(DeliveryType::X2AndX3);
            let d_id = dest.d_id;
            destinations.create(dest).unwrap();

            let details = task(DeliveryType::X2AndX3, vec![d_id]);
            let x_id = details.x_id;
            tasks.activate(details).unwrap();
            tasks.mark_intercept(x_id);

            tasks.deactivate(x_id).unwrap();
            destinations.remove(d_id).unwrap();
        }

        assert_eq!(tasks.len(), baseline_tasks, "task store did not drain");
        assert_eq!(
            destinations.len(),
            baseline_destinations,
            "destination store did not drain"
        );
    }

    #[test]
    fn replace_all_swaps_the_provisioned_set() {
        let (destinations, tasks) = stores_with_content();
        let dest = destination(DeliveryType::X2Only);
        let d_id = dest.d_id;
        destinations.create(dest).unwrap();
        tasks.activate(task(DeliveryType::X2Only, vec![d_id])).unwrap();

        let replacement = task(DeliveryType::X2Only, vec![d_id]);
        let new_id = replacement.x_id;
        tasks.replace_all(vec![replacement]);

        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks.ids(), vec![new_id]);
    }

    #[test]
    fn deactivate_all_clears_every_task() {
        let (destinations, tasks) = stores_with_content();
        let dest = destination(DeliveryType::X2Only);
        let d_id = dest.d_id;
        destinations.create(dest).unwrap();
        for _ in 0..5 {
            tasks.activate(task(DeliveryType::X2Only, vec![d_id])).unwrap();
        }
        assert_eq!(tasks.deactivate_all(), 5);
        assert!(tasks.is_empty());
    }
}
