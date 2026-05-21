//! Technitium API response types.
//!
//! Technitium's DNS API returns JSON responses whose shapes vary by endpoint.
//! Most endpoints return flat `Value` responses that are handled directly by the
//! service trait implementations. Record list responses are normalized via
//! [`core::dns::responses::ListRecordsResponse::from_value()`]; no
//! Technitium-specific response struct is needed for the current feature set.
//!
//! If a future feature requires parsing a structured Technitium-specific
//! response type (e.g., dashboard stats, zone metadata), define it here and
//! implement `TryFrom<Value>` or a dedicated constructor.
