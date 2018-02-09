use types::*;

use failure::Error;
use yubihsm_sys::{self, yh_capabilities, yh_session};

use std::cell::Cell;
use std::ffi::CString;

macro_rules! generate_key {
    ($name:ident, $yh_func:ident) => (
        pub fn $name(
            &self,
            key_id: u16,
            label: &str,
            domains: &[Domain],
            capabilities: &[Capability],
            algorithm: Algorithm
        ) -> Result<(), Error> {
            let mut key_id_ptr = key_id;
            let c_label = CString::new(label)?;
            let lib_domains = DomainParam::from(Vec::from(domains));
            let lib_caps = yh_capabilities::from(Vec::from(capabilities));

            unsafe {
                match ReturnCode::from(yubihsm_sys::$yh_func(
                    self.this.get(),
                    &mut key_id_ptr,
                    c_label.as_ptr(),
                    lib_domains.0,
                    &lib_caps,
                    algorithm.into(),
                )) {
                    ReturnCode::Success => Ok(()),
                    e => Err(format_err!("$name failed: {}", e)),
                }
            }
        }
    )
}

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

    pub fn get_random(&self, len: usize) -> Result<Vec<u8>, Error> {
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
                bail!("yh_util_get_random failed: {}", ret);
            }

            if out_size != len {
                bail!("data sizes didn't match");
            }

            out.set_len(out_size);
        }

        Ok(out)
    }

    pub fn sign_ecdsa<T: AsRef<[u8]>>(&self, key_id: u16, data: T) -> Result<Vec<u8>, Error> {
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
                bail!("couldn't sign_ecdsa: {}", ret);
            }

            out.set_len(out_size);
        }

        Ok(out)
    }

    pub fn sign_eddsa<T: AsRef<[u8]>>(&self, key_id: u16, data: T) -> Result<Vec<u8>, Error> {
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
                bail!("couldn't sign_eddsa: {}", ret);
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
    ) -> Result<Vec<u8>, Error> {
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
                bail!("couldn't sign_pkcs1v1_5: {}", ret);
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
    ) -> Result<Vec<u8>, Error> {
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
                bail!("couldn't sign_pss: {}", ret);
            }

            out.set_len(out_size);
        }

        Ok(out)
    }

    generate_key!(generate_key_ec, yh_util_generate_key_ec);

    generate_key!(generate_key_ed, yh_util_generate_key_ed);

    generate_key!(generate_key_hmac, yh_util_generate_key_hmac);

    generate_key!(generate_key_rsa, yh_util_generate_key_rsa);

    pub fn generate_wrapkey(
        &self,
        key_id: u16,
        label: &str,
        domains: &[Domain],
        capabilities: &[Capability],
        delegated_capabilities: &[Capability],
        algorithm: Algorithm,
    ) -> Result<(), Error> {
        let mut key_id_ptr = key_id;
        let c_label = CString::new(label)?;
        let lib_domains = DomainParam::from(Vec::from(domains));
        let lib_caps = yh_capabilities::from(Vec::from(capabilities));
        let lib_delegated_caps = yh_capabilities::from(Vec::from(delegated_capabilities));

        unsafe {
            match ReturnCode::from(yubihsm_sys::yh_util_generate_key_wrap(
                self.this.get(),
                &mut key_id_ptr,
                c_label.as_ptr(),
                lib_domains.0,
                &lib_caps,
                algorithm.into(),
                &lib_delegated_caps,
            )) {
                ReturnCode::Success => Ok(()),
                e => Err(format_err!("generate_key_wrap failed: {}", e)),
            }
        }
    }

    pub fn create_authkey(
        &self,
        key_id: u16,
        label: &str,
        domains: &[Domain],
        capabilities: &[Capability],
        delegated_capabilities: &[Capability],
        password: &str,
    ) -> Result<(), Error> {
        let mut key_id_ptr = key_id;
        let c_label = CString::new(label)?;
        let c_pass = CString::new(password)?;
        let c_pass_slice = c_pass.as_bytes();
        let lib_domains = DomainParam::from(Vec::from(domains));
        let lib_caps = yh_capabilities::from(Vec::from(capabilities));
        let lib_delegated_caps = yh_capabilities::from(Vec::from(delegated_capabilities));

        unsafe {
            match ReturnCode::from(yubihsm_sys::yh_util_import_authkey(
                self.this.get(),
                &mut key_id_ptr,
                c_label.as_ptr(),
                lib_domains.0,
                &lib_caps,
                &lib_delegated_caps,
                c_pass_slice.as_ptr(),
                c_pass_slice.len(),
            )) {
                ReturnCode::Success => Ok(()),
                e => Err(format_err!("util_import_authkey failed: {}", e)),
            }
        }
    }

    pub fn put_opaque_object(
        &self,
        object_id: u16,
        label: &str,
        domains: &[Domain],
        capabilities: &[Capability],
        algorithm: Algorithm,
        contents: &[u8],
    ) -> Result<(), Error> {
        let mut obj_id_ptr = object_id;
        let c_label = CString::new(label)?;
        let lib_domains = DomainParam::from(Vec::from(domains));
        let lib_caps = yh_capabilities::from(Vec::from(capabilities));

        unsafe {
            match ReturnCode::from(yubihsm_sys::yh_util_import_opaque(
                self.this.get(),
                &mut obj_id_ptr,
                c_label.as_ptr(),
                lib_domains.0,
                &lib_caps,
                algorithm.into(),
                contents.as_ptr(),
                contents.len(),
            )) {
                ReturnCode::Success => Ok(()),
                e => Err(format_err!("util_import_opaque failed: {}", e)),
            }
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        unsafe {
            yubihsm_sys::yh_util_close_session(self.this.get());
            yubihsm_sys::yh_destroy_session(&mut self.this.get());
        }
    }
}
