use errors::*;

use yubihsm_sys::{self, yh_session, yh_rc_YHR_SUCCESS};

use std::cell::Cell;

#[derive(Clone, Debug)]
pub struct Session {
    this: Cell<*mut yh_session>,
}

impl Session {
    pub(crate) fn new(this: *mut yh_session) -> Session {
        Session {
            this: Cell::new(this),
        }
    }
}
