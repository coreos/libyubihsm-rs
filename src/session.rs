// Copyright 2018 CoreOS, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use types::*;

use failure::Error;
use yubihsm_sys::{self, yh_algorithm, yh_capabilities, yh_object_descriptor, yh_object_type,
                  yh_session};

use std::cell::Cell;
use std::ffi::{CStr, CString};
use std::ops::Deref;
use std::os::raw::c_char;
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicPtr, Ordering};

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
            let lib_domains = DomainParam::from(domains);
            let lib_caps = yh_capabilities::from(capabilities);

            unsafe {
                match ReturnCode::from(yubihsm_sys::$yh_func(
                    self.this.load(Ordering::Relaxed),
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

// In order to implement `Drop` correctly here, we need to move the `AtomicPtr<yh_session>` into
// its own type. This lets us avoid relying on `Arc::strong_count()`. According to the Rust docs on
// `Arc::strong_count()`:
//      This method by itself is safe, but using it correctly requires extra care. Another thread
//      can change the strong count at any time, including potentially between calling this method
//      and acting on the result.
// So, we need to run the session-teardown functions when the Arc drops its contents, instead of
// trying to reimplement part of Arc's `Drop`.
#[derive(Debug)]
struct SessionPtr(AtomicPtr<yh_session>);

impl Drop for SessionPtr {
    fn drop(&mut self) {
        unsafe {
            yubihsm_sys::yh_util_close_session(self.0.load(Ordering::Relaxed));
            yubihsm_sys::yh_destroy_session(&mut self.0.load(Ordering::Relaxed));
        }
    }
}

impl Deref for SessionPtr {
    type Target = AtomicPtr<yh_session>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Represents a `Session` with the HSM.
///
/// The `Session` is where the bulk of the YubiHSM's functionality is found. A `Session` is needed
/// to perform any cryptographic or device administration tasks.
#[derive(Clone, Debug)]
pub struct Session {
    this: Arc<SessionPtr>,
    _unsync_marker: Cell<()>,
}

impl Session {
    pub(crate) fn new(this: *mut yh_session) -> Session {
        Session {
            this: Arc::new(SessionPtr(AtomicPtr::new(this))),
            _unsync_marker: Cell::new(()),
        }
    }

    pub fn list_objects(&self) -> ListObjectsQuery {
        ListObjectsQuery::new(&self)
    }

    fn list_objects_query(
        &self,
        id: u16,
        object_type: yh_object_type,
        domains: DomainParam,
        capabilities: yh_capabilities,
        algorithm: yh_algorithm,
        label: *const c_char,
        limit: usize,
    ) -> Result<Vec<ObjectInfo>, Error> {
        let mut objects: Vec<yh_object_descriptor> = Vec::with_capacity(limit);
        let mut n_objects = objects.capacity();

        let rc = unsafe {
            ReturnCode::from(yubihsm_sys::yh_util_list_objects(
                self.this.load(Ordering::Relaxed),
                id,
                object_type,
                domains.0,
                &capabilities,
                algorithm,
                label,
                objects.as_mut_ptr(),
                &mut n_objects,
            ))
        };

        if rc != ReturnCode::Success {
            bail!("yh_util_list_objects failed: {}", rc);
        }

        unsafe { objects.set_len(n_objects) };
        objects.shrink_to_fit();

        objects
            .into_iter()
            .map(ObjectInfo::try_from_yh_object_descriptor)
            .collect::<Result<Vec<_>, Error>>()
    }

    pub fn delete_object(&self, obj_id: u16, obj_type: ObjectType) -> Result<(), Error> {
        unsafe {
            match ReturnCode::from(yubihsm_sys::yh_util_delete_object(
                self.this.load(Ordering::Relaxed),
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
                self.this.load(Ordering::Relaxed),
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
                self.this.load(Ordering::Relaxed),
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
                self.this.load(Ordering::Relaxed),
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
                self.this.load(Ordering::Relaxed),
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
                self.this.load(Ordering::Relaxed),
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
        let lib_domains = DomainParam::from(domains);
        let lib_caps = yh_capabilities::from(capabilities);
        let lib_delegated_caps = yh_capabilities::from(delegated_capabilities);

        unsafe {
            match ReturnCode::from(yubihsm_sys::yh_util_generate_key_wrap(
                self.this.load(Ordering::Relaxed),
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
        let lib_domains = DomainParam::from(domains);
        let lib_caps = yh_capabilities::from(capabilities);

        unsafe {
            match ReturnCode::from(yubihsm_sys::yh_util_import_key_ec(
                self.this.load(Ordering::Relaxed),
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
        let lib_domains = DomainParam::from(domains);
        let lib_caps = yh_capabilities::from(capabilities);

        unsafe {
            match ReturnCode::from(yubihsm_sys::yh_util_import_key_ed(
                self.this.load(Ordering::Relaxed),
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
        let lib_domains = DomainParam::from(domains);
        let lib_caps = yh_capabilities::from(capabilities);

        unsafe {
            match ReturnCode::from(yubihsm_sys::yh_util_import_key_hmac(
                self.this.load(Ordering::Relaxed),
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
        let lib_domains = DomainParam::from(domains);
        let lib_caps = yh_capabilities::from(capabilities);

        unsafe {
            match ReturnCode::from(yubihsm_sys::yh_util_import_key_rsa(
                self.this.load(Ordering::Relaxed),
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
        let lib_domains = DomainParam::from(domains);
        let lib_caps = yh_capabilities::from(capabilities);
        let lib_delegated_caps = yh_capabilities::from(delegated_capabilities);

        unsafe {
            match ReturnCode::from(yubihsm_sys::yh_util_import_key_wrap(
                self.this.load(Ordering::Relaxed),
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
        let lib_domains = DomainParam::from(domains);
        let lib_caps = yh_capabilities::from(capabilities);
        let lib_delegated_caps = yh_capabilities::from(delegated_capabilities);

        unsafe {
            match ReturnCode::from(yubihsm_sys::yh_util_import_authkey(
                self.this.load(Ordering::Relaxed),
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
        let lib_domains = DomainParam::from(domains);
        let lib_caps = yh_capabilities::from(capabilities);

        unsafe {
            match ReturnCode::from(yubihsm_sys::yh_util_import_opaque(
                self.this.load(Ordering::Relaxed),
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
                self.this.load(Ordering::Relaxed),
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
                self.this.load(Ordering::Relaxed),
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
                self.this.load(Ordering::Relaxed),
                log_index,
            )) {
                ReturnCode::Success => Ok(()),
                e => bail!("util_set_log_index failed: {}", e),
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct ListObjectsQuery<'a> {
    session: &'a Session,
    id: Option<u16>,
    object_type: Option<ObjectType>,
    domains: Option<&'a [Domain]>,
    capabilities: Option<&'a [Capability]>,
    algorithm: Option<Algorithm>,
    label: Option<&'a str>,
    limit: Option<usize>,
}

impl<'a> ListObjectsQuery<'a> {
    fn new(session: &'a Session) -> ListObjectsQuery {
        ListObjectsQuery {
            session,
            id: None,
            object_type: None,
            domains: None,
            capabilities: None,
            algorithm: None,
            label: None,
            limit: None,
        }
    }

    pub fn id(self, id: u16) -> ListObjectsQuery<'a> {
        ListObjectsQuery {
            id: Some(id),
            ..self
        }
    }

    pub fn object_type(self, object_type: ObjectType) -> ListObjectsQuery<'a> {
        ListObjectsQuery {
            object_type: Some(object_type),
            ..self
        }
    }

    pub fn domains(self, domains: &'a [Domain]) -> ListObjectsQuery<'a> {
        ListObjectsQuery {
            domains: Some(domains),
            ..self
        }
    }

    pub fn capabilities(self, capabilities: &'a [Capability]) -> ListObjectsQuery<'a> {
        ListObjectsQuery {
            capabilities: Some(capabilities),
            ..self
        }
    }

    pub fn algorithm(self, algorithm: Algorithm) -> ListObjectsQuery<'a> {
        ListObjectsQuery {
            algorithm: Some(algorithm),
            ..self
        }
    }

    pub fn label(self, label: &'a str) -> ListObjectsQuery<'a> {
        ListObjectsQuery {
            label: Some(label),
            ..self
        }
    }

    pub fn limit(self, limit: usize) -> ListObjectsQuery<'a> {
        ListObjectsQuery {
            limit: Some(limit),
            ..self
        }
    }

    pub fn execute(self) -> Result<Vec<ObjectInfo>, Error> {
        let id = self.id.unwrap_or(0);
        let object_type: yh_object_type = self.object_type.map(|x| x.into()).unwrap_or(0);
        let domains = self.domains
            .map(DomainParam::from)
            .unwrap_or(DomainParam(0));
        let capabilities = self.capabilities
            .map(yh_capabilities::from)
            .unwrap_or(yh_capabilities::from(&[]));
        let algorithm = self.algorithm.map(yh_algorithm::from).unwrap_or(0);
        let label = self.label
            .map(|l| CStr::from_bytes_with_nul(l.as_bytes()).map(|c| c.as_ptr()))
            .unwrap_or(Ok(ptr::null()))?;
        let limit = self.limit.unwrap_or(256);

        self.session.list_objects_query(
            id,
            object_type,
            domains,
            capabilities,
            algorithm,
            label,
            limit,
        )
    }
}
