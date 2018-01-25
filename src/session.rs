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

    pub fn sign_ecdsa<T: AsRef<[u8]>>(&self, key_id: u16, data: T) -> Result<Vec<u8>> {
        // The libyubihsm documentation makes no mention of how large this buffer should be, and
        // there don't appear to be any constants related to signature size, so this is just a
        // rough guess.
        let mut out_size: usize = 512;
        let mut out: Vec<u8> = Vec::with_capacity(out_size);

        let data_slice = data.as_ref();

        unsafe {
            let ret = ReturnCode::from(yubihsm_sys::yh_util_sign_ecdsa(
                self.this.get(),
                key_id,
                data_slice.as_ptr(),
                data_slice.len(),
                out.as_mut_ptr(),
                &mut out_size,
            ));

            if ret != ReturnCode::Success {
                bail!(format!("couldn't sign_ecdsa: {}", ret));
            }

            out.set_len(out_size);
        }

        Ok(out)
    }

    pub fn sign_eddsa<T: AsRef<[u8]>>(&self, key_id: u16, data: T) -> Result<Vec<u8>> {
        // The libyubihsm documentation makes no mention of how large this buffer should be, and
        // there don't appear to be any constants related to signature size, so this is just a
        // rough guess.
        let mut out_size: usize = 512;
        let mut out: Vec<u8> = Vec::with_capacity(out_size);

        let data_slice = data.as_ref();

        unsafe {
            let ret = ReturnCode::from(yubihsm_sys::yh_util_sign_eddsa(
                self.this.get(),
                key_id,
                data_slice.as_ptr(),
                data_slice.len(),
                out.as_mut_ptr(),
                &mut out_size,
            ));

            if ret != ReturnCode::Success {
                bail!(format!("couldn't sign_eddsa: {}", ret));
            }

            out.set_len(out_size);
        }

        Ok(out)
    }

    pub fn sign_pkcs1v1_5<T: AsRef<[u8]>>(
        &self,
        key_id: u16,
        hashed: bool,
        data: T,
    ) -> Result<Vec<u8>> {
        // The libyubihsm documentation makes no mention of how large this buffer should be, and
        // there don't appear to be any constants related to signature size, so this is just a
        // rough guess.
        let mut out_size: usize = 512;
        let mut out: Vec<u8> = Vec::with_capacity(out_size);

        let data_slice = data.as_ref();

        unsafe {
            let ret = ReturnCode::from(yubihsm_sys::yh_util_sign_pkcs1v1_5(
                self.this.get(),
                key_id,
                hashed,
                data_slice.as_ptr(),
                data_slice.len(),
                out.as_mut_ptr(),
                &mut out_size,
            ));

            if ret != ReturnCode::Success {
                bail!(format!("couldn't sign_pkcs1v1_5: {}", ret));
            }

            out.set_len(out_size);
        }

        Ok(out)
    }

    pub fn sign_pss<T: AsRef<[u8]>>(
        &self,
        key_id: u16,
        salt_len: usize,
        mgf1_algorithm: Algorithm,
        data: T,
    ) -> Result<Vec<u8>> {
        // The libyubihsm documentation makes no mention of how large this buffer should be, and
        // there don't appear to be any constants related to signature size, so this is just a
        // rough guess.
        let mut out_size: usize = 512;
        let mut out: Vec<u8> = Vec::with_capacity(out_size);

        let data_slice = data.as_ref();

        unsafe {
            let ret = ReturnCode::from(yubihsm_sys::yh_util_sign_pss(
                self.this.get(),
                key_id,
                data_slice.as_ptr(),
                data_slice.len(),
                out.as_mut_ptr(),
                &mut out_size,
                salt_len,
                mgf1_algorithm.into(),
            ));

            if ret != ReturnCode::Success {
                bail!(format!("couldn't sign_pss: {}", ret));
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
