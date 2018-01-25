#[macro_use]
extern crate error_chain;

mod yubihsm_sys {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]

    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

mod errors;
mod types;
mod yubihsm;
mod connector;
mod session;

pub use errors::*;
pub use types::*;
pub use yubihsm::*;
pub use connector::*;
pub use session::*;

// Re-exports from the bindgen bindings
pub use yubihsm_sys::yh_capabilities;
