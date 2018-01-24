use errors::*;
use types::*;

use yubihsm_sys::{self, yh_session};

use std::cell::Cell;

/// Represents a `Session` with the HSM.
///
/// The `Session` is where the bulk of the YubiHSM's functionality is found. A `Session` is needed
/// to perform any cryptographic or device administration tasks.
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

    pub fn get_random(&self, len: usize) -> Result<Vec<u8>> {
        let mut out: Vec<u8> = Vec::with_capacity(len);
        let mut out_size: usize = len;

        unsafe {
            let ret = ReturnCode::from(yubihsm_sys::yh_util_get_random(
                self.this.get(),
                len,
                out.as_mut_ptr(),
                &mut out_size,
            ));

            if ret != ReturnCode::Success {
                bail!(format!("yh_util_get_random failed: {}", ret));
            }

            if out_size != len {
                bail!(format!("data sizes didn't match"));
            }

            out.set_len(out_size);
        }

        Ok(out)
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
