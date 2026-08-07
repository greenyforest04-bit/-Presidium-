//! Presidium Proto - Protobuf definitions
//! Generated types land with `generate` task in Phase 0 Week 5

#![forbid(unsafe_code)]

pub mod messages {
    include!(concat!(env!("OUT_DIR"), "/presidium.rs"));
}