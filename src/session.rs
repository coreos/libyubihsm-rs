use errors::*;
use types::*;

use yubihsm_sys::{self, yh_session};

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

impl Drop for Session {
    fn drop(&mut self) {
        unsafe {
            let rc = ReturnCode::from(yubihsm_sys::yh_util_close_session(self.this.get()));

            if rc != ReturnCode::Success {
                panic!("failed to close session: {}", rc);
            }

            let rc = ReturnCode::from(yubihsm_sys::yh_destroy_session(&mut self.this.get()));

            if rc != ReturnCode::Success {
                panic!("failed to destroy session: {}", rc);
            }
        }
    }
}
