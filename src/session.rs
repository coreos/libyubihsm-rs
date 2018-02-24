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

    pub fn delete_object(&self, obj_id: u16, obj_type: ObjectType) -> Result<(), Error> {
        unsafe {
            match ReturnCode::from(yubihsm_sys::yh_util_delete_object(
                self.this.get(),
                obj_id,
                obj_type.into(),
            )) {
                ReturnCode::Success => Ok(()),
                e => bail!("util_delete_object failed: {}", e),
            }
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

    pub fn put_key_ec<T: AsRef<[u8]>>(
        &self,
        key_id: u16,
        label: &str,
        domains: &[Domain],
        capabilities: &[Capability],
        algorithm: Algorithm,
        s: T,
    ) -> Result<(), Error> {
        let mut key_id_ptr = key_id;
        let c_label = CString::new(label)?;
        let lib_domains = DomainParam::from(Vec::from(domains));
        let lib_caps = yh_capabilities::from(Vec::from(capabilities));

        unsafe {
            match ReturnCode::from(yubihsm_sys::yh_util_import_key_ec(
                self.this.get(),
                &mut key_id_ptr,
                c_label.as_ptr(),
                lib_domains.0,
                &lib_caps,
                algorithm.into(),
                s.as_ref().as_ptr(),
            )) {
                ReturnCode::Success => Ok(()),
                e => bail!("couldn't import_key_rsa: {}", e),
            }
        }
    }

    pub fn put_key_ed<T: AsRef<[u8]>>(
        &self,
        key_id: u16,
        label: &str,
        domains: &[Domain],
        capabilities: &[Capability],
        algorithm: Algorithm,
        k: T,
    ) -> Result<(), Error> {
        let mut key_id_ptr = key_id;
        let c_label = CString::new(label)?;
        let lib_domains = DomainParam::from(Vec::from(domains));
        let lib_caps = yh_capabilities::from(Vec::from(capabilities));

        unsafe {
            match ReturnCode::from(yubihsm_sys::yh_util_import_key_ed(
                self.this.get(),
                &mut key_id_ptr,
                c_label.as_ptr(),
                lib_domains.0,
                &lib_caps,
                algorithm.into(),
                k.as_ref().as_ptr(),
            )) {
                ReturnCode::Success => Ok(()),
                e => bail!("couldn't import_key_rsa: {}", e),
            }
        }
    }

    pub fn put_key_hmac<T: AsRef<[u8]>>(
        &self,
        key_id: u16,
        label: &str,
        domains: &[Domain],
        capabilities: &[Capability],
        algorithm: Algorithm,
        key: T,
    ) -> Result<(), Error> {
        let mut key_id_ptr = key_id;
        let c_label = CString::new(label)?;
        let lib_domains = DomainParam::from(Vec::from(domains));
        let lib_caps = yh_capabilities::from(Vec::from(capabilities));

        unsafe {
            match ReturnCode::from(yubihsm_sys::yh_util_import_key_hmac(
                self.this.get(),
                &mut key_id_ptr,
                c_label.as_ptr(),
                lib_domains.0,
                &lib_caps,
                algorithm.into(),
                key.as_ref().as_ptr(),
                key.as_ref().len(),
            )) {
                ReturnCode::Success => Ok(()),
                e => bail!("couldn't import_key_rsa: {}", e),
            }
        }
    }

    // TODO(csssuf): refactor put_key design to properly solve this lint?
    #[allow(too_many_arguments)]
    pub fn put_key_rsa<T: AsRef<[u8]>>(
        &self,
        key_id: u16,
        label: &str,
        domains: &[Domain],
        capabilities: &[Capability],
        algorithm: Algorithm,
        p: T,
        q: T,
    ) -> Result<(), Error> {
        let mut key_id_ptr = key_id;
        let c_label = CString::new(label)?;
        let lib_domains = DomainParam::from(Vec::from(domains));
        let lib_caps = yh_capabilities::from(Vec::from(capabilities));

        unsafe {
            match ReturnCode::from(yubihsm_sys::yh_util_import_key_rsa(
                self.this.get(),
                &mut key_id_ptr,
                c_label.as_ptr(),
                lib_domains.0,
                &lib_caps,
                algorithm.into(),
                p.as_ref().as_ptr(),
                q.as_ref().as_ptr(),
            )) {
                ReturnCode::Success => Ok(()),
                e => bail!("couldn't import_key_rsa: {}", e),
            }
        }
    }

    // TODO(csssuf): refactor put_key design to properly solve this lint?
    #[allow(too_many_arguments)]
    pub fn put_wrapkey<T: AsRef<[u8]>>(
        &self,
        key_id: u16,
        label: &str,
        domains: &[Domain],
        capabilities: &[Capability],
        delegated_capabilities: &[Capability],
        algorithm: Algorithm,
        key: T,
    ) -> Result<(), Error> {
        let mut key_id_ptr = key_id;
        let c_label = CString::new(label)?;
        let lib_domains = DomainParam::from(Vec::from(domains));
        let lib_caps = yh_capabilities::from(Vec::from(capabilities));
        let lib_delegated_caps = yh_capabilities::from(Vec::from(delegated_capabilities));

        unsafe {
            match ReturnCode::from(yubihsm_sys::yh_util_import_key_wrap(
                self.this.get(),
                &mut key_id_ptr,
                c_label.as_ptr(),
                lib_domains.0,
                &lib_caps,
                algorithm.into(),
                &lib_delegated_caps,
                key.as_ref().as_ptr(),
                key.as_ref().len(),
            )) {
                ReturnCode::Success => Ok(()),
                e => bail!("couldn't import_key_rsa: {}", e),
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

    pub fn get_pubkey(&self, key_id: u16) -> Result<PublicKey, Error> {
        // Per the Yubico documentation, the largest type of data is a public key for a 4096-bit
        // RSA key, which is 0x400 bytes long.
        // https://developers.yubico.com/YubiHSM2/Commands/Get_Pubkey.html

        let mut data: Vec<u8> = Vec::with_capacity(0x400);
        let mut data_length = data.capacity();
        let mut algorithm = 0;

        let rc = unsafe {
            ReturnCode::from(yubihsm_sys::yh_util_get_pubkey(
                self.this.get(),
                key_id,
                data.as_mut_ptr(),
                &mut data_length,
                &mut algorithm,
            ))
        };

        if rc != ReturnCode::Success {
            bail!("util_get_pubkey failed: {}", rc);
        }

        unsafe { data.set_len(data_length) };
        data.shrink_to_fit();

        match Algorithm::from(algorithm) {
            Algorithm::Rsa2048 | Algorithm::Rsa3072 | Algorithm::Rsa4096 => {
                Ok(PublicKey::Rsa(data))
            }
            Algorithm::EcP224
            | Algorithm::EcP256
            | Algorithm::EcP384
            | Algorithm::EcP521
            | Algorithm::EcK256
            | Algorithm::EcBp256
            | Algorithm::EcBp384
            | Algorithm::EcBp512 => {
                // Yubico documentation claims `data` contains points X and Y here, so we'll trust
                // it and split down the middle.
                let split_point = data.len() / 2;
                let point_y = data.split_off(split_point);

                Ok(PublicKey::Ecc(data, point_y))
            }
            Algorithm::EcEd25519 => Ok(PublicKey::Edc(data)),
            a => bail!("get_pubkey: unexpected algorithm type {}", a),
        }
    }

    pub fn get_logs(&self) -> Result<Log, Error> {
        let mut entries: Vec<yubihsm_sys::yh_log_entry> =
            Vec::with_capacity(yubihsm_sys::YH_MAX_LOG_ENTRIES as usize);
        let mut n_entries = entries.capacity();
        let mut unlogged_boots = 0;
        let mut unlogged_auths = 0;

        let rc = unsafe {
            ReturnCode::from(yubihsm_sys::yh_util_get_logs(
                self.this.get(),
                &mut unlogged_boots,
                &mut unlogged_auths,
                entries.as_mut_ptr(),
                &mut n_entries,
            ))
        };

        if rc != ReturnCode::Success {
            bail!("util_get_logs failed: {}", rc);
        }

        unsafe { entries.set_len(n_entries) };
        entries.shrink_to_fit();

        Ok(Log {
            unlogged_boots: unlogged_boots,
            unlogged_auths: unlogged_auths,
            log_entries: entries.into_iter().map(LogEntry::from).collect::<Vec<_>>(),
        })
    }

    pub fn set_log_index(&self, log_index: u16) -> Result<(), Error> {
        unsafe {
            match ReturnCode::from(yubihsm_sys::yh_util_set_log_index(
                self.this.get(),
                log_index,
            )) {
                ReturnCode::Success => Ok(()),
                e => bail!("util_set_log_index failed: {}", e),
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
